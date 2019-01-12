* /security (website)
* security.md (in repo)
* `<link>` tag (website)
* composer.json (Composer control this?)
* /.well-known/security.txt (website, already defined)
* /.well-known/security.yml (website, something we define)
* Directory of vulns in repository? Used by composer?

Website things, could we get them on github projects e.g. github.com/symfony/symfony/.well-known/security.yml

## What are we linking to?

* Machine readable feed thing?
* Human page listing vulns (e.g. symfony's blog category)
* repository following set standard structure

Machine Readable URLs:
* `https://github.com/FriendsOfPHP/security-advisories.git/{vendor}/{component}/{id}.{format}`
* `git@github.com:FriendsOfPHP/security-advisories.git/{vendor}/{component}/{id}.{format}`
* `https://symfony.com/advisories/{component}/{id}.{format}`

Maybe link to human place, and machine place.
e.g.
```
<link rel="security" href="/security">
<link rel="machine-advisories" href="https://github.com/FriendsOfPHP/security-advisories.git/{vendor}/{component}/{id}.{format}">
<link rel="human-advisories" href="https://symfony.com/blog/category/security-advisories">
```

## Things to consider:
* Some projects just on github
* Some projects don't use a VCS/Github
* FriendsOfPHP/security-advisories
* Cannot rely on composer.json format
* Projects using services like hackerone

## security.yml idea
```yaml
contact: "mailto:info@php-fig.org"
encryption: "https://php-fig.org/pgp_key.asc"
hiring: "https://php-fig.org/hiring"
policy: "https://php-fig.org/security"
signature: "https://php-fig.org/.well-known/security.txt.sig"
advisories:
    list: "https://raw.githubusercontent.com/FriendsOfPHP/security-advisories/master/drupal/list.txt"
    machine: "https://github.com/FriendsOfPHP/security-advisories.git/{vendor}/{component}/{id}.{format}"
    human: "https://symfony.com/blog/category/security-advisories"
```

## security.txt
https://tools.ietf.org/html/draft-foudil-securitytxt-04

Example:
```
Contact: mailto:info@php-fig.org
Encryption: https://php-fig.org/pgp_key.asc 
Acknowledgements: https://php-fig.org/hall-of-fame
Hiring: https://php-fig.org/hiring
Policy: https://php-fig.org/security
Permission: none
Signature: https://php-fig.org/.well-known/security.txt.sig
```

