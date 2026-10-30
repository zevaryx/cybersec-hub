// news.js: sorts the episode list by date (data-date="YYYY-MM"), latest or oldest first.
// The choice is kept in the address (?sort=oldest) so a sorted link can be shared.
const list = document.getElementById('episodes');
const nav = document.getElementById('sort-nav');
const buttons = [...nav.querySelectorAll('button[data-sort]')];

function sort(order) {
  const items = [...list.children].sort((a, b) => a.dataset.date.localeCompare(b.dataset.date));
  if (order !== 'oldest') items.reverse();
  list.append(...items);
  for (const b of buttons) b.setAttribute('aria-pressed', String(b.dataset.sort === (order === 'oldest' ? 'oldest' : 'latest')));
}

for (const b of buttons) {
  b.addEventListener('click', () => {
    const order = b.dataset.sort;
    const url = new URL(location.href);
    if (order === 'oldest') url.searchParams.set('sort', 'oldest'); else url.searchParams.delete('sort');
    history.replaceState(null, '', url);
    sort(order);
  });
}

nav.hidden = false;
sort(new URLSearchParams(location.search).get('sort') === 'oldest' ? 'oldest' : 'latest');
