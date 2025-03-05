# **Projeto de Escaneamento de Rede e Captura de Pacotes**

## **Descrição**

Este projeto consiste em um script desenvolvido para realizar tarefas essenciais de segurança de rede, incluindo o escaneamento de hosts e portas, a validação de direções IP, a captura de pacotes e a verificação de segurança com base na norma ISO/IEC 27002. O sistema permite que usuários validem, monitorem e analisem redes, realizando escaneamentos em múltiplas máquinas e salvando os dados para análise posterior.

## **Funcionalidades**

- **Escaneamento de Rede**: Permite escanear uma ou várias IPs para detectar hosts ativos.
- **Escaneamento de Portas**: Realiza o escaneamento de portas abertas em uma determinada IP ou faixa de IPs.
- **Captura de Pacotes**: Captação de pacotes de rede para diagnóstico e análise de tráfego.
- **Verificação de Segurança**: Realiza verificações de segurança conforme a norma ISO/IEC 27002 utilizando ferramentas de escaneamento como o Nmap.
- **Armazenamento de Pacotes**: Possibilidade de salvar os pacotes capturados em arquivos `.pcap` para análise posterior.

## **Caso de Uso**

Este script é ideal para empresas ou profissionais de segurança da informação que buscam realizar auditorias e testes de penetração em suas redes, validando a integridade das configurações de segurança e a existência de vulnerabilidades. Ele pode ser usado para:
- **Auditoria de Rede**: Verificar quais dispositivos estão conectados e se as portas abertas representam riscos de segurança.
- **Diagnóstico de Tráfego**: Capturar pacotes de rede para realizar análises detalhadas sobre o tráfego, identificando comportamentos anômalos.
- **Verificação de Conformidade**: Ajudar na verificação de conformidade com normas de segurança como a ISO/IEC 27002.

## **Como Funciona**

O script permite ao usuário realizar as seguintes ações:
1. **Inserir Endereços IP**: O usuário fornece uma lista de endereços IP a serem escaneados.
2. **Definir Rango de Portas**: O usuário define quais portas deseja escanear (ou escolhe escanear todas as portas).
3. **Escolher Interface de Rede**: O script detecta as interfaces de rede disponíveis e permite ao usuário selecionar qual será usada para a captura de pacotes.
4. **Captura de Pacotes**: O script pode capturar pacotes de rede durante um tempo determinado, permitindo o monitoramento em tempo real.
5. **Salvar Pacotes**: Caso o usuário deseje, os pacotes capturados podem ser armazenados em um arquivo `.pcap` para futuras análises.

## **Tecnologias Utilizadas**

- **Nmap**: Para escanear hosts e portas de rede.
- **Scapy**: Para captura e manipulação de pacotes de rede.
- **Psutil**: Para obter informações sobre as interfaces de rede.
- **Python**: A linguagem de programação utilizada para desenvolver o script, com bibliotecas padrão como `socket`, `re`, `logging`, e `concurrent.futures` para facilitar o desenvolvimento.
