# password-analyzer
A privacy-friendly command-line tool that checks basic password strength and
can generate a secure password. It uses only the Python standard library.

## Features

- Hides password input while typing.
- Does not save names or passwords.
- Checks password length and character variety.
- Gives clear improvement advice.
- Generates 9-character passwords using the `secrets` module.

## Run it

```bash
python password_analyzer.py
```

## Notes

The strength estimate is only a guide. Use a unique password for every account
and store generated passwords in a trusted password manager.
