# AuthenticatorApp

**AuthenticatorApp** é um aplicativo de autenticação em duas etapas (TOTP) com interface gráfica baseada em PyQt5, suporte multiusuário e integração com múltiplos bancos de dados (SQLite, MySQL e PostgreSQL). Ele oferece gerenciamento de usuários, cópia rápida de códigos TOTP, criptografia de configurações e execução segura na bandeja do sistema no Windows.

---

## 🧰 Funcionalidades

- 🔒 **Autenticação por TOTP (Time-based One-Time Password)**
- 👥 **Gerenciamento de usuários com níveis de permissão (admin / user)**
- 🔐 **Criptografia de dados sensíveis com `cryptography.Fernet`**
- 💾 **Suporte a múltiplos bancos de dados**:
  - SQLite
  - MySQL
  - PostgreSQL
- 🛡️ **Login com validação de senha (bcrypt)**
- 🔄 **Gerador de códigos TOTP com atualização automática**
- 🖱️ **Acesso via bandeja do sistema (tray icon)**
- 🛠️ **Interface para edição de configurações criptografadas**
- 📋 **Cópia rápida do código padrão para a área de transferência**
- 🌙 **Interface gráfica moderna com tema escuro**

---

## 🖥️ Requisitos do Sistema

- **Sistema Operacional**: Apenas Windows
- **Python**: 3.7 ou superior
- **Dependências**: Veja a seção [Instalação](#instalação)

---

## 📦 Instalação

1. **Clone o repositório**:
   ```bash
   git clone https://github.com/arlindovs/AutenticadorWin.git
   cd AuthenticatorApp
   ```

2. **Crie um ambiente virtual (opcional, mas recomendado)**:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Instale as dependências**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Execute o aplicativo**:
   ```bash
   python app.py
   ```

---

## 📚 Como Usar

### Primeira Execução

- Na primeira inicialização, será solicitado que você configure o tipo de banco de dados.
- Um usuário administrador padrão será criado automaticamente com as seguintes credenciais:

  | Usuário | Senha |
  |--------|-------|
  | admin  | admin |

> **Importante**: Altere essa senha após o primeiro login.

### Modo de Operação

- O app roda com uma interface gráfica.
- Ao fechar a janela, ele se minimiza na **bandeja do sistema**.
- Através do ícone da bandeja, você pode:
  - Restaurar o app
  - Copiar o código TOTP padrão
  - Encerrar o aplicativo

---

## 🧪 Estrutura do Projeto

```
.
├── app.py              # Código principal do aplicativo
├── requirements.txt    # Lista de dependências
├── config.json         # Arquivo de configuração criptografado (gerado após setup)
├── encryption_key.key  # Chave de criptografia gerada automaticamente
```

---

## 🔐 Segurança

- As senhas dos usuários são armazenadas usando hashing com `bcrypt`.
- As configurações de conexão com banco de dados são **criptografadas** com chave `Fernet`, e armazenadas no `config.json`.

---

## 🧑‍💻 Tecnologias Utilizadas

- Python 3
- PyQt5
- pyotp
- bcrypt
- cryptography
- pyperclip
- pystray
- pillow
- MySQL Connector
- psycopg2 (PostgreSQL)

---

## ⚠️ Limitações

- O aplicativo **funciona apenas em sistemas Windows**.
- Apenas usuários com perfil `admin` podem gerenciar usuários e configurações.
- Atualmente, o app não possui suporte a temas claros nem responsividade para múltiplas resoluções.

---

## 📌 To-Do Futuro

- [ ] Suporte a sistemas Linux e MacOS
- [ ] Backup e exportação dos códigos
- [ ] Suporte a temas claros
- [ ] Integração com autenticação biométrica ou Windows Hello

---

## 📄 Licença

Este projeto é distribuído sob a licença MIT. Consulte o arquivo `LICENSE` para mais detalhes.

---

## 📫 Contato

Caso tenha dúvidas ou sugestões, sinta-se à vontade para entrar em contato:

- 💼 github.com/arlindovs
- 📧 arlindovicente@gmail.com

---