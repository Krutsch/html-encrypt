# html-enscrypt

A zero config and one dependency tool to enscript html files.
This is a heavy modified clone of [staticrypt](https://github.com/robinmoisson/staticrypt).

<p align="center">
  <img src="login.png">
  <a class="text-center" href="https://html-encrypt.netlify.app">Live Example</a>
<p>


## Installation

```bash
npm i html-enscrypt
```

## Execute

```bash
npx html-enscrypt <path/index.html>
```

Note: running the command will modify the file.


## Options

- You will be asked to enter the Password

  <p align="center">
    <img src="brute-force.png">
    <a class="text-center" href="https://www.hivesystems.com/blog/examining-the-lastpass-breach-through-our-password-table">Please consider using a safe password</a>
  <p>

- Additionally, you can bring in your own template
  ```html
  <form method="post">
      PW: <input type="password" name="" id="">
      <button type="submit">Login</button>
  </form>
  ```


- You can also add --removeHead in order to remove the content of the head for the output file. This might be needed for some SPAs.
  ```bash
  npx html-enscrypt --removeHead <path/index.html>
  ```

- You can also add --no-minify in order to not use html-minifier-terser.
  ```bash
  npx html-enscrypt --no-minify <path/index.html>
  ```
