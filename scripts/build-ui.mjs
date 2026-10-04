import {build} from 'esbuild';
import {transform} from 'lightningcss';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const result = await build({
  absWorkingDir: root,
  entryPoints: ['web/components/environment-form.jsx'], outdir: 'web/ui',
  bundle: true, format: 'esm', target: ['es2022'], jsx: 'automatic', minify: true,
  define: {'process.env.NODE_ENV': '"production"'}, legalComments: 'eof', write: false,
  plugins: [{
    name: 'combobox-modal-accessibility',
    setup(build) {
      build.onLoad({filter: /react-aria\/dist\/private\/combobox\/useComboBox\.mjs$/}, async ({path}) => {
        const source = await readFile(path, 'utf8');
        // A mobile ComboBox already has a modal that hides its surroundings.
        // Hiding them twice mixes inert/aria-hidden reference counts and leaves
        // the form hidden after closing: github.com/adobe/react-spectrum/issues/8934.
        const before = 'if (state.isOpen) return (0, $58196c8d6a1f38fc$export$1c3ebcada18427bf)';
        if (!source.includes(before)) throw new Error('Review the mobile ComboBox accessibility fix after upgrading React Aria.');
        return {contents: source.replace(before, before.replace('state.isOpen', "state.isOpen && popoverRef.current?.getAttribute('role') !== 'dialog'")), loader: 'js'};
      });
    }
  }],
  banner: {js: '/*! React Spectrum and React Aria: Copyright Adobe.\nComboBox adapted to let its mobile modal manage accessibility.\n' + await readFile(new URL('../node_modules/@adobe/react-spectrum/LICENSE', import.meta.url), 'utf8') + '\n*/'}
});
await mkdir(new URL('../web/ui/', import.meta.url), {recursive: true});
for (const file of result.outputFiles) {
  const contents = file.path.endsWith('.css') ? transform({filename: file.path, code: file.contents, minify: true}).code : file.contents;
  if (process.argv.includes('--check')) {
    const existing = await readFile(file.path);
    if (!existing.equals(Buffer.from(contents))) throw new Error('Run npm run build:ui to update ' + file.path);
  } else await writeFile(file.path, contents);
  console.log(file.path.slice(root.length) + ': ' + Math.round(contents.length / 1024) + ' kB');
}
