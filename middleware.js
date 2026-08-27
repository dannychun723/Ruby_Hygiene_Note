// Gate the whole site behind one shared login. Runs at the edge before any
// file is served, so the note tool is never sent to an unauthenticated browser.
export const config = { matcher: '/:path*' };

const ASK = new Response('Authentication required', {
  status: 401,
  headers: { 'WWW-Authenticate': 'Basic realm="Ruby\'s clinical notes", charset="UTF-8"' },
});

export default function middleware(request) {
  const expected = process.env.SITE_PASSWORD;
  if (!expected) return ASK.clone(); // ponytail: no password set = locked, not open

  const header = request.headers.get('authorization') || '';
  if (!header.startsWith('Basic ')) return ASK.clone();

  // "user:pass" — the username is ignored, only the password has to match.
  const [, password] = atob(header.slice(6)).split(/:(.*)/s);
  // ponytail: plain compare. The secret is 80 bits of random over TLS, so
  // network timing leaks nothing usable. Swap for a constant-time compare if
  // this ever guards more than one hygienist's own notes.
  if (password !== expected) return ASK.clone();
}
