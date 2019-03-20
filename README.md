# graveyard

These packages has (almost) no chance to see the world. This is a feed of unfinished ideas and broken cross-compilation code, so all this stuff is stored here just for history.

## Usage

* [Install](https://github.com/Entware/Entware/wiki/Compile-packages-from-sources#pick-up-one-of-supported-platform) Entware buildroot,
* Un-comment following line in `feeds.conf`:
```
src-git graveyard https://github.com/Entware/graveyard.git
```
* Run `make package/symlinks` to refresh local copy of available packages,
* Pick necessary package from `make menuconfig` menu and save changes,
* Run `make V=s package/<package name>/compile` to build it,
* Take `package_x.yy.ipk` from `bin` folder.
