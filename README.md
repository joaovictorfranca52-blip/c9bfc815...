# Painel Secreto

Projeto com dois acessos:

- `http://localhost:3000/admin` — painel do administrador
- `http://localhost:3000/access` — página pública, somente leitura/desbloqueio

## Segurança implementada

- O painel administrativo exige senha.
- A sessão do administrador usa cookie `HttpOnly`.
- As mensagens são armazenadas com **AES-256-GCM**.
- As respostas usadas para desbloquear mensagens são armazenadas como hash derivado com **scrypt**, não em texto puro.
- A página pública não recebe o texto original até a resposta correta ser enviada ao servidor.

## Como rodar

1. Instale o Node.js 18 ou superior.
2. Abra a pasta do projeto em um terminal.
3. Copie `.env.example` para `.env`.
4. **Troque `ADMIN_PASSWORD`, `SESSION_SECRET` e `DATA_SECRET`.**
5. Rode:

```bash
npm install
npm start
```

6. Abra:
   - Admin: `http://localhost:3000/admin`
   - Visitante: `http://localhost:3000/access`

## Senha inicial

Se você não criar um `.env`, a senha padrão será:

`diggou</>`

**Não publique usando essa senha padrão.**

## Para colocar online

Você pode hospedar este projeto em um serviço que execute Node.js, por exemplo Render, Railway ou VPS. Depois de publicado, terá URLs como:

- `https://seusite.com/admin`
- `https://seusite.com/access`

Configure as variáveis de ambiente no serviço de hospedagem e use HTTPS.

## Observação importante

A segurança "só eu consigo editar" depende de o projeto estar rodando em um servidor sob seu controle, com senha forte e variáveis secretas protegidas. Não compartilhe o acesso do painel administrativo.
