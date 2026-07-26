export function zeroize(buf: Buffer | null | undefined): void {
  if (buf && buf.length > 0) {
    buf.fill(0);
  }
}
