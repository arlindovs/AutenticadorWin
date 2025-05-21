# Autenticador TOTP

Um aplicativo autenticador de código TOTP (Time-based One-Time Password) com interface gráfica, inspirado no Google Authenticator, mas com funcionalidades adicionais como gerenciamento de usuários, tema escuro, e integração com a bandeja do sistema no Windows.

## Funcionalidades

- **Autenticação TOTP**: Gere códigos TOTP para múltiplas contas.
- **Gerenciamento de Usuários**: Administradores podem adicionar, editar, excluir e resetar senhas de usuários.
- **Tema Escuro**: Interface com design minimalista e tema escuro.
- **Integração com Bandeja do Sistema**: Minimize o aplicativo para a bandeja no Windows, com opções para restaurar, copiar código padrão e sair.
- **Logoff**: Faça logoff para voltar à tela de login.
- **Suporte a Banco de Dados**: Escolha entre SQLite ou MySQL para armazenar usuários e segredos TOTP.

## Requisitos

- **Sistema Operacional**: Windows (o aplicativo é compatível apenas com Windows devido à integração com a bandeja do sistema).
- **Python**: Versão 3.12 ou superior.
- **MySQL** (opcional): Caso opte por usar MySQL, um servidor MySQL deve estar disponível.

## Instalação

1. **Clone o Repositório** (caso aplicável):
   ```bash
   git clone <URL_DO_REPOSITORIO>
   cd autenticador-totp
   ```

2. **Crie um Ambiente Virtual** (opcional, mas recomendado):
   ```bash
   python -m venv venv
   source venv/Scripts/activate  # No Windows
   # ou
   source venv/bin/activate  # No Linux/Mac
   ```

3. **Instale as Dependências**:
   Certifique-se de ter o arquivo `requirements.txt` no diretório do projeto e execute:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configuração do Banco de Dados**:
   - O aplicativo suporta SQLite (padrão) ou MySQL.
   - Para MySQL, você precisará de um servidor MySQL rodando. Durante a primeira execução, o aplicativo perguntará qual banco de dados usar:
     - **SQLite**: Nenhuma configuração adicional é necessária.
     - **MySQL**:
       - **Host**: `20.0.0.11`
       - **Usuário**: `mastersys`
       - **Senha**: `king2sys`
       - **Porta**: `3399`

## Uso

1. **Execute o Aplicativo**:
   ```bash
   python authenticator.py
   ```

2. **Primeira Execução**:
   - Se o arquivo `config.json` não existir, você será solicitado a configurar o banco de dados (SQLite ou MySQL).
   - Após configurar, o aplicativo criará um usuário administrador padrão:
     - **Usuário**: `admin`
     - **Senha**: `admin`

3. **Login**:
   - Faça login com as credenciais acima.
   - Você pode alterar a senha do administrador na tela de login clicando em "Alterar Senha".

4. **Funcionalidades Principais**:
   - **Adicionar Código TOTP**: Clique no botão "+" para adicionar um novo código TOTP.
   - **Copiar Código**: Clique em um código para copiá-lo para a área de transferência.
   - **Definir Código Padrão**: No menu "⋮", selecione "Definir como Padrão" para escolher um código padrão.
   - **Gerenciar Usuários** (apenas admin): No menu "⋮", selecione "Gerenciar Usuários" para adicionar, editar, excluir ou resetar senhas de usuários.
   - **Resetar Senha**: Na tela de gerenciamento de usuários, selecione um usuário e clique em "Resetar Senha" para definir a senha como "123".
   - **Logoff**: Clique no botão "Logoff" para voltar à tela de login.
   - **Bandeja do Sistema**:
     - Feche a janela para minimizar o aplicativo para a bandeja.
     - Clique com o botão direito no ícone da bandeja para:
       - Copiar o código padrão.
       - Restaurar o aplicativo.
       - Sair do aplicativo.

## Solução de Problemas

- **Erro ao Conectar ao MySQL**:
  - Certifique-se de que o servidor MySQL está rodando e acessível em `20.0.0.11:3399`.
  - Verifique as credenciais (`mastersys`/`king2sys`).
  - Para reconfigurar, delete o arquivo `config.json` e execute o aplicativo novamente.

- **Ícone da Bandeja Não Aparece**:
  - Certifique-se de que está executando no Windows.
  - Verifique se `pystray` e `pillow` estão instalados corretamente (`pip show pystray pillow`).
  - Tente executar o aplicativo como administrador.

- **Reset de Senha Não Funciona**:
  - Certifique-se de que um usuário está selecionado na tabela de gerenciamento de usuários.
  - Verifique se o usuário admin tem permissões para atualizar a tabela `users` no banco de dados.

## Contribuições

Contribuições são bem-vindas! Para contribuir:

1. Faça um fork do repositório.
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`).
3. Faça suas alterações e commit (`git commit -m "Adiciona nova funcionalidade"`).
4. Envie um pull request.

## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo `LICENSE` para mais detalhes (se aplicável).

## Contato

Para dúvidas ou sugestões, entre em contato através do repositório ou envie um e-mail para `seu-email@example.com`.

---

*Última atualização: 21 de maio de 2025*