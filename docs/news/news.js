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

// ---------------------------------------------------------------- easter eggs (listed in plans/EASTER_EGGS.md)
function egg(msg) {
  let t = document.querySelector('.hub-toast');
  if (!t) {
    t = document.createElement('p');
    t.className = 'hub-toast';
    t.setAttribute('role', 'status');
    document.body.append(t);
  }
  t.textContent = msg;
  t.classList.remove('show');
  void t.offsetWidth;                                   // restart the animation
  t.classList.add('show');
  clearTimeout(t.hide);
  t.hide = setTimeout(() => t.classList.remove('show'), 6000);   // reduced motion has no animation to end it
}

// sorting the list over and over
let sorts = 0;
for (const b of buttons) {
  b.addEventListener('click', () => {
    sorts++;
    if (sorts !== 6) return;
    if (list.children.length === 1) egg('Sorting one episode: done instantly, every time. Come back next month for a harder problem.');
    else egg('Sorted again. Same news either way, sadly.');
  });
}

console.log('%c// BREAKING NEWS', 'color:#ff2e88;font:700 16px monospace');
console.log('Local person opens browser console. Experts say this is a good habit. Every story slide lists its sources at the bottom: check our work too.');
