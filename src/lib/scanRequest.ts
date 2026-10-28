import axios from 'axios';

/** Wake the API before sending a URL; never replay a scan automatically. */
export async function requestScan(api: string, target: string, signal: AbortSignal, onPhase: (message: string) => void) {
  onPhase('Conectando ao servidor… No primeiro acesso, isso pode levar até um minuto. Você pode cancelar.');
  await axios.get(api.replace(/\/api\/?$/, '/'), { timeout: 65000, signal });
  if (signal.aborted) throw new axios.CanceledError();
  onPhase('Conferindo sinais locais e bases de ameaças…');
  return axios.post(`${api}/scan/url`, { url: target }, {
    headers: { 'Content-Type': 'application/json' }, timeout: 30000, signal,
  });
}
