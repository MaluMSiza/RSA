# RSA Encryption and Decryption Algorithm

Implementação simples do algoritmo de criptografia RSA (Rivest-Shamir-Adleman) em JAVA, sem depender de bibliotecas externas.

## Descrição

O RSA é um dos primeiros e mais conhecidos sistemas de criptografia de chave pública. Ele é amplamente utilizado para comunicação segura pela internet, incluindo e-mails, mensagens instantâneas e transações online.

Este repositório contém uma implementação simples do algoritmo RSA, incluindo funções para gerar chaves, criptografar e descriptografar mensagens.

## Funcionalidades

- Geração de chaves RSA com tamanhos personalizáveis (atualmente configurado para 4096 bits).
- Criptografia e descriptografia de mensagens de texto.
- Comunicação entre um servidor e um cliente TCP utilizando chaves RSA.

## Uso

1. Clone o repositório:
2. Entre na pasta SERVER:
3.   Lembre se compilar o ALgoritmoRSA antes de executar o server pode ser o comando: " cd criptografia" e "javac AlgoritmoRSA.java"
4.   Compile e execute o Server "javac TCPServer.java" e "java TCPServer"
5. Entre na pasta CLIENT:
6.   Lembre se compilar o ALgoritmoRSA antes de executar o client pode ser o comando: " cd criptografia" e "javac AlgoritmoRSA.java"
7.   Compile e execute o Client "javac TCPServer.java" e "java TCPServer"

obs: Nao deixe o TCPCliente e o TCPServer na mesma pasta.



