import { APP_VERSION, RELEASE_DATE, RELEASE_NOTES } from './release';

export function ReleaseVersion() {
  return <small data-app-version={APP_VERSION} title={RELEASE_NOTES} style={{ display: 'inline-block', fontSize: '11px', lineHeight: 1.6, fontWeight: 400 }}>Versão {APP_VERSION} · atualizado em {RELEASE_DATE}</small>;
}
