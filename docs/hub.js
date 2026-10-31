// hub.js: the track tabs and reading progress.
// Tabs: clicking a track shows only that track; the choice is kept in the address (#developer) so it can be shared.
// Without JavaScript every track shows, one after another.
// Progress: a deck marks itself read when you reach its last slide (shared/deck.js), saved in this browser only
// as localStorage "hub-read:<folder>". Each card also has a toggle to fix it by hand. Nothing is sent anywhere.
// A track's bar has one segment per talk, lit once it's read.
const tabs = [...document.querySelectorAll('.track-tabs a[data-track]')];
const tracks = [...document.querySelectorAll('section.track')];
const store = {
  get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { v ? localStorage.setItem(k, v) : localStorage.removeItem(k); } catch (e) { /* storage blocked: fine */ } },
};
const keyOf = card => 'hub-read:' + new URL(card.querySelector('h3 a').href).pathname.split('/').filter(Boolean).pop();
const isRead = card => !!store.get(keyOf(card));

// a toggle on every finished talk, featured cards included
for (const card of document.querySelectorAll('.feat-card, .talk-card')) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'read-toggle';
  b.addEventListener('click', () => {
    store.set(keyOf(card), isRead(card) ? '' : new Date().toISOString().slice(0, 10));
    draw();
  });
  card.querySelector('.card-links').append(b);
}

function draw() {
  for (const card of document.querySelectorAll('.feat-card, .talk-card')) {
    const read = isRead(card);
    card.classList.toggle('read', read);
    const b = card.querySelector('.read-toggle');
    b.setAttribute('aria-pressed', String(read));
    b.textContent = read ? '✓ Read' : 'Mark as read';
    b.title = read ? 'Read in this browser. Click to unmark.' : 'Saved in this browser only';
  }
  for (const t of tracks) {
    const cards = [...t.querySelectorAll('.talk-card')];
    const read = cards.filter(isRead).length;
    t.querySelector('.track-progress').innerHTML = '<span class="segs" aria-hidden="true">' +
      cards.map(c => isRead(c) ? '<i class="on"></i>' : '<i></i>').join('') +
      `</span><span class="progress-text">You've read ${read} of ${cards.length} talk${cards.length === 1 ? '' : 's'}</span>`;
    const tab = tabs.find(a => a.dataset.track === t.id);
    if (tab) tab.querySelector('.tab-count').textContent = `${read}/${cards.length}`;
  }
}

function show(name) {
  if (!tracks.some(t => t.id === name)) name = tracks[0].id;
  for (const t of tracks) t.hidden = t.id !== name;
  for (const a of tabs) {
    if (a.dataset.track === name) a.setAttribute('aria-current', 'true');
    else a.removeAttribute('aria-current');
  }
}

for (const a of tabs) {
  a.addEventListener('click', e => {
    e.preventDefault();
    history.replaceState(null, '', '#' + a.dataset.track);
    show(a.dataset.track);
  });
}
draw();
show(location.hash.slice(1));
// coming back from a deck in another tab: pick up what it marked
addEventListener('storage', e => { if (!e.key || e.key.startsWith('hub-read:')) draw(); });
addEventListener('pageshow', e => { if (e.persisted) draw(); });

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

// the Konami code
const KONAMI = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight', 'b', 'a'];
let typed = [];
let word = '';
addEventListener('keydown', e => {
  if (e.target.closest && e.target.closest('input, textarea, select')) return;
  typed = [...typed, e.key.length === 1 ? e.key.toLowerCase() : e.key].slice(-KONAMI.length);
  if (typed.join() === KONAMI.join()) {
    document.body.classList.add('storm');
    setTimeout(() => document.body.classList.remove('storm'), 1600);
    egg('↑↑↓↓←→←→BA: 30 extra lives (Contra, 1988). Security has no cheat codes, but Crypto 101 comes close.');
  }
  // typing "sudo"
  word = (word + (e.key.length === 1 ? e.key.toLowerCase() : ' ')).slice(-4);
  if (word === 'sudo') egg('you are not in the sudoers file. This incident will be reported. (It won\'t. Nothing here is sent anywhere.)');
});

// click the title: each click shifts it one letter, like a Caesar cipher
const title = document.querySelector('.hub-head .glitch');
const TITLE = title.textContent;
let shift = 0;
title.closest('h1').setAttribute('aria-label', TITLE);
title.addEventListener('click', () => {
  shift = (shift + 1) % 26;
  const out = TITLE.replace(/[a-z]/gi, ch => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode((ch.charCodeAt(0) - base + shift) % 26 + base);
  });
  title.textContent = out;
  title.dataset.text = out;
  if (shift === 13) egg('ROT13: shift 13 again and you\'re back. Some people call that encryption. Please don\'t.');
  if (shift === 0) egg('26 shifts: back where you started. A Caesar cipher has only 25 keys worth trying.');
});

// poking the "More coming soon" tile
let pokes = 0;
for (const tile of document.querySelectorAll('.more-soon')) {
  tile.addEventListener('click', () => {
    pokes++;
    if (pokes === 3) egg('Patience. Good things take time: password hashes like Argon2 are slow on purpose, too.');
    if (pokes === 10) egg('Ten clicks. Refreshing won\'t make it come out faster either.');
  });
}

// reading every talk on the page
// (only at the moment it happens, not on every visit afterwards)
const allRead = () => [...document.querySelectorAll('.feat-card, .talk-card')].every(isRead);
let caughtUp = allRead();
const checkAll = () => {
  const all = allRead();
  if (all && !caughtUp) egg('ACHIEVEMENT UNLOCKED: Caught Up. You\'ve read every talk here. More coming soon. Really.');
  caughtUp = all;
};
for (const b of document.querySelectorAll('.read-toggle')) b.addEventListener('click', checkAll);
addEventListener('storage', checkAll);

console.log('%c// CYBERSEC HUB', 'color:#ff2e88;font:700 16px monospace');
console.log('Hello, curious one. This page hides a few secrets: one is a very old cheat code, one a very old cipher, and one needs admin rights you don\'t have.');
