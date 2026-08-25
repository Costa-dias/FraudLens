# 🛡️ FraudLens · Segurança antes do clique

<div align="center">

[![Status do Deploy](https://img.shields.io/badge/Deploy-Online-success?style=for-the-badge&logo=render)](https://fraudlens-code.onrender.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-5.0+-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)

**Uma ferramenta inteligente e anônima para verificação de links, prints e QR Codes suspeitos antes de você cair em golpes.**

</div>

---

## 🚀 Sobre o Projeto

O **FraudLens** foi desenvolvido para ajudar usuários comuns e equipes a analisarem rapidamente a credibilidade de páginas da Web, capturas de tela (prints) ou códigos QR. Com uma interface limpa e focada em privacidade, o sistema cruza dados locais e informações de fontes de segurança para emitir um veredito claro.

### ✨ Principais Recursos

* **🌐 Análise de URLs:** Verifica a estrutura do link, certificados e sinais de alerta em tempo real.
* **📸 Leitura de Print / Fotos:** Permite enviar evidências visuais de mensagens suspeitas.
* **📱 Leitor de QR Code integrado:** Lê códigos diretamente de imagens ou vídeos curtos enviados pelo usuário.
* **🔒 Privacidade em primeiro lugar:** Uso totalmente anônimo, sem exigência de cadastro e com histórico salvo apenas no armazenamento local do navegador (*localStorage*).
* **🚨 Geração de Denúncia Anônima:** Cria um resumo formatado do golpe detectado para fácil compartilhamento com familiares ou autoridades.

---

## 🛠️ Tecnologias Utilizadas

Este repositório contém o **Frontend** da aplicação:
* **React** com **TypeScript**
* **Vite** (Build tool rápida e otimizada)
* **Axios** (Requisições HTTP para a API)
* **Tailwind CSS / Estilos customizados** (Design responsivo e moderno)
* **Lucide React** (Ícones)
* **jsQR** (Decodificação de QR codes via navegador)

---

## 📂 Estrutura do Repositório

```text
fraudlens-code/
├── src/
│   ├── App.tsx          # Componente principal e lógica de interface/API
│   ├── main.tsx         # Ponto de entrada da aplicação React
│   ├── index.css        # Estilos globais do sistema
│   └── vite-env.d.ts    # Tipagens do Vite
├── public/              # Assets estáticos
├── package.json         # Dependências e scripts do projeto
└── README.md            # Documentação do projeto
