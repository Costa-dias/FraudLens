import React, { useState } from 'react';

export function RadarBanner() {
  const [isVisible, setIsVisible] = useState(true);

  if (!isVisible) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-sm rounded-2xl bg-gradient-to-r from-blue-600 to-indigo-600 p-4 text-white shadow-2xl transition-all duration-300 hover:scale-105">
      <button
        onClick={() => setIsVisible(false)}
        className="absolute -top-2 -right-2 flex h-6 w-6 items-center justify-center rounded-full bg-slate-900 text-xs font-bold text-white shadow-md hover:bg-red-600"
        title="Fechar"
      >
        ✕
      </button>
      <div className="flex items-start space-x-3">
        <span className="text-2xl">🚨</span>
        <div>
          <h4 className="text-sm font-bold">Radar de Golpes</h4>
          <p className="mt-1 text-xs text-blue-100">
            Para verificar os golpes em alta no brasil acesse:{' '}
            <a
              href="https://radar-de-golpes-hub.xadoondias.workers.dev"
              target="_blank"
              rel="noopener noreferrer"
              className="font-semibold underline hover:text-yellow-300"
            >
              radar-de-golpes-hub.xadoondias.workers.dev
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
