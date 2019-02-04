# sensedia-clientTotp
Simulador de Google Authenticator no Browser
Esta é a implementação do Sensedia Authenticator em página HTML e validação no Javascript. Este é um programa que imitat o Google Authenticator gerando senhas TOTPs a partir de uma chave obtida de algum site (pode-se copiar a chave digitável do programa servidor entregue neste mesmo exercício).

As bibliotecas JQuery e Bootstrap são utilizadas apenas para formatação de tela

Para utilizar:

    (Cadastro) Selecionar uma senha, digitar ou copiar uma chave secreta para o TOTP e salvar.
    (Login) Gerar uma senha TOTP (esta página apresenta uma nova senha a cada 30 segundos).

O arquivo es5TOTP.js contém as funções de gerar e validar os TOTP.
