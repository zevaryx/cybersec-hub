// hub.js: clicking a track name shows only that track; clicking it again shows them all.
// The chosen track is kept in the address (#developer) so a filtered link can be shared.
const links = [...document.querySelectorAll('.track-nav a[data-track]')];
const tracks = [...document.querySelectorAll('section.track')];

function show(name) {
  const known = tracks.some(t => t.id === name);
  for (const t of tracks) t.hidden = known && t.id !== name;
  for (const a of links) a.setAttribute('aria-pressed', String(known && a.dataset.track === name));
}

for (const a of links) {
  a.addEventListener('click', e => {
    e.preventDefault();
    const name = a.getAttribute('aria-pressed') === 'true' ? '' : a.dataset.track;
    history.replaceState(null, '', name ? '#' + name : location.pathname + location.search);
    show(name);
  });
}
show(location.hash.slice(1));
