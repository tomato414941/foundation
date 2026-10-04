import { fail, HttpError } from './errors.mjs';

const repositoryPattern = /^[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)?$/;
const tagPattern = /^[\w][\w.-]{0,127}$/;
const invalid = () => fail(400, 'invalid_image_search', 'イメージの検索条件を確認してください。');
const unavailable = () => fail(503, 'image_catalog_unavailable', 'Docker Hubに接続できません。しばらく待ってからお試しください。');
function parameters(query, page) {
  if (typeof query !== 'string' || query.length > 200 || /[\x00-\x1f]/.test(query)) invalid();
  if (!/^\d{1,5}$/.test(String(page)) || Number(page) < 1) invalid();
  return { query: query.trim(), page: Number(page) };
}

// Public image discovery for the environment picker. Only Docker's fixed hosts are contacted;
// Foundation credentials never accompany these requests. Cache the small, normalized result pages.
export class EnvironmentImages {
  constructor(fetcher = fetch) { this.fetcher = fetcher; this.pages = new Map(); }

  async read(url, project) {
    const cached = this.pages.get(url);
    if (cached && cached.until > Date.now()) return cached.value;
    const value = (async () => {
      try {
        const response = await this.fetcher(url, { headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(8000) });
        if (!response.ok) {
          await response.body?.cancel();
          if (response.status === 404) fail(404, 'image_repository_missing', 'イメージが見つかりません。');
          unavailable();
        }
        const chunks = []; let length = 0;
        for await (const chunk of response.body) {
          length += chunk.length;
          if (length > 2_000_000) unavailable();
          chunks.push(chunk);
        }
        const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!Array.isArray(data.results)) unavailable();
        return project(data);
      } catch (error) {
        if (error instanceof HttpError) throw error;
        unavailable();
      }
    })();
    if (this.pages.size >= 200) this.pages.delete(this.pages.keys().next().value);
    this.pages.set(url, { value, until: Date.now() + 300_000 });
    try { return await value; }
    catch (error) { if (this.pages.get(url)?.value === value) this.pages.delete(url); throw error; }
  }

  search(query = '', page = 1) {
    ({ query, page } = parameters(query, page));
    if (!query) return Promise.resolve({ images: [], next: null });
    // The same search endpoint used by Docker Engine's registry search.
    const url = 'https://index.docker.io/v1/search?' + new URLSearchParams({ q: query, n: '12', page: String(page) });
    return this.read(url, data => ({
      images: data.results.slice(0, 12).filter(item => typeof item?.name === 'string' && item.name.length <= 200 && repositoryPattern.test(item.name))
        .map(item => ({ name: item.name, description: typeof item.description === 'string' ? item.description.slice(0, 500) : '', official: item.is_official === true })),
      next: Number(data.num_pages) > page ? page + 1 : null,
    }));
  }

  tags(repository, query = '', page = 1) {
    ({ query, page } = parameters(query, page));
    if (typeof repository !== 'string' || repository.length > 200 || !repositoryPattern.test(repository)) invalid();
    const [namespace, name] = repository.includes('/') ? repository.split('/') : ['library', repository];
    const url = `https://hub.docker.com/v2/namespaces/${namespace}/repositories/${name}/tags?` + new URLSearchParams({ page_size: '50', page: String(page), ...(query ? { name: query } : {}) });
    return this.read(url, data => ({
      tags: data.results.slice(0, 50).filter(item => typeof item?.name === 'string' && tagPattern.test(item.name) && repository.length + 1 + item.name.length <= 255 &&
        Array.isArray(item.images) && item.images.some(image => image.os === 'linux' && image.architecture === 'amd64'))
        .map(item => ({ name: item.name })),
      next: data.next ? page + 1 : null,
    }));
  }
}
