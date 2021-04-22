# simpleca

Autoridade Certificadora simples escrita em Go.

## Instalação

### Binários

Os binários para Windows e Linux podem ser obtidos na seção de Releases deste repositório.

### Fontes

Para instalar a partir dos fontes é necessário ter o compilador de [Go](https://golang.org) versão 1.13 ou superior.

Com isso pode ser executado o seguinte comando:

```shell
go get go.mps.com.br/gti/simpleca
```

Ou

```shell
git clone https://git.mps.com.br/gti/simpleca
cd simpleca
go install
```

## Geração de versão

Para gerar uma nova versão é necessário:

* Criar um novo tag usando o git

  * Neste projeto usamos [semantic version](https://semver.org), então as versões estão no formato x.y.z.

* Executar o script `build.sh` que vai gerar os binários no diretório `dist`.

* Fazer o push da tag para o servidor como no comando abaixo:

  ```shell
  git push --all
  git push --tags
  ```

* Criar o novo release no servidor.

  * No campo `Tag name` deve ser informado o tag que foi enviado para o servidor no passo anterior.

  * No campo `Title` pode ser informada uma mensagem como `Versão x.y.z`.

  * Os binários que estão no diretório `dist` devem ser adicionados no release (arraste os arquivos para a seção `Drop files or click here to upload.`).
