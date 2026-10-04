import React, {useEffect, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {Provider} from '@adobe/react-spectrum/Provider';
import {defaultTheme} from '@adobe/react-spectrum/defaultTheme';
import {DialogContainer} from '@adobe/react-spectrum/DialogContainer';
import {Dialog} from '@adobe/react-spectrum/Dialog';
import {Heading} from '@adobe/react-spectrum/Heading';
import {Content} from '@adobe/react-spectrum/Content';
import {Form} from '@adobe/react-spectrum/Form';
import {TextField} from '@adobe/react-spectrum/TextField';
import {Picker} from '@adobe/react-spectrum/Picker';
import {ComboBox, Item} from '@adobe/react-spectrum/ComboBox';
import {Text} from '@adobe/react-spectrum/Text';
import {Button} from '@adobe/react-spectrum/Button';
import {ButtonGroup} from '@adobe/react-spectrum/ButtonGroup';
import {useAsyncList} from '@adobe/react-spectrum/useAsyncList';
import {Disclosure, DisclosureTitle, DisclosurePanel} from '@adobe/react-spectrum/Accordion';
import './environment-form.css';

const theme = {...defaultTheme, global: {...defaultTheme.global, foundation: 'foundation-ui'}};

// Catalog requests and committed values belong to the app. Spectrum owns the
// search field, list, mobile tray, keyboard navigation and focus restoration.
function CatalogField({label, emptyText, value, onChange, load, autoSelect = false, t}) {
  const [text, setText] = useState(value?.label || '');
  const committed = useRef(value);
  committed.current = value;
  const list = useAsyncList({
    async load({signal, filterText = '', cursor, items}) {
      if (filterText && !cursor) {
        await new Promise(resolve => {
          const timer = setTimeout(resolve, 250);
          signal.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, {once: true});
        });
      }
      signal.throwIfAborted();
      const result = await load(filterText.trim(), cursor || 1, signal);
      return {...result, items: cursor ? result.items.filter(item => !items.some(previous => previous.id === item.id)) : result.items};
    }
  });
  useEffect(() => { setText(value?.label || ''); }, [value]);
  useEffect(() => {
    const item = list.items.find(item => item.isDefault);
    if (autoSelect && !value && !list.filterText && item) onChange(item);
  }, [autoSelect, value, list.items, list.filterText, onChange]);
  const error = list.loadingState === 'error' ? list.error : null;
  const results = error
    ? [{id: 'retry', label: t('client.environment.retry'), description: error.message}]
    : list.loadingState === 'filtering' ? []
    : list.items.length || list.isLoading ? list.items : [{id: 'empty', label: emptyText}];
  // Retain the selected item while filtering so the library can restore it on cancel.
  const items = value && !results.some(item => item.id === value.id) ? [...results, value] : results;
  return <ComboBox label={label} width="100%" items={items}
    description={error?.message}
    selectedKey={value?.id || null} inputValue={text} menuTrigger="focus"
    loadingState={list.loadingState} onLoadMore={error ? undefined : list.loadMore} disabledKeys={['empty']}
    autoComplete="off" autoCapitalize="none" spellCheck={false}
    onInputChange={next => {
      setText(next);
      list.setFilterText(next === committed.current?.label ? '' : next);
    }}
    onOpenChange={(open, trigger) => {
      if (open && trigger !== 'input') { setText(''); list.setFilterText(''); }
      if (!open) setText(committed.current?.label || '');
    }}
    onSelectionChange={key => {
      if (key === 'retry') { list.reload(); return; }
      const item = items.find(item => item.id === key && item.id !== 'empty');
      if (item) {
        setText(item.label);
        if (item.id !== committed.current?.id) { committed.current = item; onChange(item); }
      }
    }}>
    {item => <Item key={item.id} textValue={item.label}>
      <Text>{item.title || item.label}</Text>
      {item.description && <Text slot="description">{item.official ? t('client.environment.officialImage') + ' · ' : ''}{item.description}</Text>}
    </Item>}
  </ComboBox>;
}

function EnvironmentForm({owner, api, t, finish}) {
  const [name, setName] = useState('');
  const [minutes, setMinutes] = useState('60');
  const [size, setSize] = useState('small');
  const [identity, setIdentity] = useState('none');
  const [image, setImage] = useState({id: 'default', kind: 'default', label: t('client.environment.defaultImage')});
  const [version, setVersion] = useState(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const submitting = useRef(false);
  const versionItem = name => ({id: name, label: name === 'latest' ? t('client.environment.defaultVersion') : name});

  async function loadImages(query, page, signal) {
    if (!query) return {items: [{id: 'default', kind: 'default', label: t('client.environment.defaultImage')}]};
    if (/[:@]/.test(query) || /^[^/]*\.[^/]*\//.test(query)) {
      return {items: /\s/.test(query) ? [] : [{id: 'custom:' + query, kind: 'custom', label: query,
        title: t('client.environment.useImage', {name: query}), description: t('client.environment.useImageName')}]};
    }
    const data = await api('/v1/environment-images?' + new URLSearchParams({query, page}), {signal});
    return {items: data.images.map(item => ({...item, id: 'hub:' + item.name, kind: 'hub', label: item.name})), cursor: data.next};
  }
  async function loadVersions(query, page, signal) {
    const data = await api('/v1/environment-images/tags?' + new URLSearchParams({repository: image.name, query, page}), {signal});
    const names = [...new Set([...(data.default_tag ? [data.default_tag] : []), ...data.tags.map(tag => tag.name)])];
    return {items: names.map(name => ({...versionItem(name), isDefault: name === data.default_tag})), cursor: data.next};
  }
  async function submit(event) {
    event.preventDefault();
    if (submitting.current) return;
    if (image.kind === 'hub' && !version) { setError(t('client.environment.chooseImageVersion')); return; }
    submitting.current = true; setPending(true); setError('');
    const seconds = Number(minutes) * 60;
    try {
      await api('/v1/principals/' + owner + '/environments', {method: 'POST', data: {
        ...(name.trim() ? {name: name.trim()} : {}),
        ...(image.kind === 'default' ? {} : {image: image.kind === 'hub' ? image.name + ':' + version.id : image.label}),
        size, identity: identity === 'none' ? null : owner,
        lifetime: {end: 'idle', idle_seconds: seconds, max_seconds: seconds}
      }});
      finish(true);
    } catch (error) { setError(error.message); }
    finally { submitting.current = false; setPending(false); }
  }
  return <DialogContainer onDismiss={() => { if (!submitting.current) finish(false); }} isKeyboardDismissDisabled={pending}>
    <Dialog size="M">
      <Heading>{t('client.environment.createTitle')}</Heading>
      <Content>
        <Form onSubmit={submit} isDisabled={pending} aria-label={t('client.environment.createTitle')}>
          <TextField label={t('client.common.optionalLabel', {label: t('client.common.name')})}
            value={name} onChange={setName} maxLength={200} autoComplete="off" width="100%" />
          <Picker label={t('client.environment.autoStop')} selectedKey={minutes} onSelectionChange={setMinutes} width="100%">
            {[15, 30, 60].map(count => <Item key={String(count)}>{t('client.environment.afterMinutes', {count})}</Item>)}
          </Picker>
          <Disclosure marginTop="size-200" isDisabled={pending}>
            <DisclosureTitle>{t('client.environment.options')}</DisclosureTitle>
            <DisclosurePanel>
              <div className="environment-fields">
                <CatalogField label={t('client.environment.image')} emptyText={t('client.environment.noImages')}
                  value={image} onChange={item => { setImage(item); setVersion(null); setError(''); }} load={loadImages} t={t} />
                {image.kind === 'hub' && <CatalogField key={image.id} label={t('client.environment.version')}
                  emptyText={t('client.environment.noVersions')} value={version} onChange={setVersion} load={loadVersions} autoSelect t={t} />}
                <Picker label={t('client.environment.size')} selectedKey={size} onSelectionChange={setSize} width="100%">
                  <Item key="small">Small</Item><Item key="medium">Medium</Item><Item key="large">Large</Item>
                </Picker>
                <Picker label={t('client.environment.permissions')} selectedKey={identity} onSelectionChange={setIdentity} width="100%">
                  <Item key="none">{t('client.environment.noAccess')}</Item><Item key="owner">{t('client.environment.ownAccess')}</Item>
                </Picker>
              </div>
            </DisclosurePanel>
          </Disclosure>
          {error && <p className="environment-error" role="alert">{error}</p>}
          <ButtonGroup align="end" marginTop="size-300">
            <Button variant="secondary" onPress={() => finish(false)}>{t('client.common.cancel')}</Button>
            <Button variant="primary" type="submit">{t(pending ? 'client.environment.creating' : 'client.environment.create')}</Button>
          </ButtonGroup>
        </Form>
      </Content>
    </Dialog>
  </DialogContainer>;
}

export function openEnvironmentForm(props) {
  const host = document.createElement('div');
  host.className = 'foundation-ui';
  document.body.append(host);
  const root = createRoot(host);
  return new Promise(resolve => {
    let settled = false;
    const finish = created => {
      if (settled) return;
      settled = true;
      props.signal.removeEventListener('abort', cancel);
      // Let the event finish before disposing the React root and its focus scope.
      queueMicrotask(() => { root.unmount(); host.remove(); resolve(created); });
    };
    const cancel = () => finish(false);
    props.signal.addEventListener('abort', cancel, {once: true});
    root.render(
      <Provider theme={theme} colorScheme="dark" locale={props.t.locale === 'ja' ? 'ja-JP' : 'en-US'}>
        <EnvironmentForm {...props} finish={finish} />
      </Provider>
    );
  });
}
