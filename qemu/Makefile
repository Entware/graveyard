#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=qemu
PKG_VERSION:=1.3.0-rc1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://wiki.qemu.org/download/
PKG_MD5SUM:=13e927be592fd574dbaeabf6e833a24b

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/qemu
	SECTION:=emulator
	CATEGORY:=Emulators
#	DEPENDS:=+libstdcpp
	TITLE:=a generic and open source machine emulator and virtualizer
	URL:=http://www.qemu.org
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/qemu/description
 QEMU is a generic and open source machine emulator and virtualizer.
endef

define Build/Configure
    (cd $(PKG_BUILD_DIR); \
	CFLAGS="$(TARGET_CFLAGS)" \
	LDFLAGS="$(TARGET_LDFLAGS)" \
	./configure \
	    --prefix="$(PKG_INSTALL_DIR)/opt" \
	    --target-list="i386-linux-user,i386-softmmu"  \
	    --cross-prefix="$(TARGET_CROSS)" \
	    --cc="$(TARGET_CC)" \
	    --host-cc="$(HOSTCC)" \
	    --objcc="$(TARGET_CC)" \
	    --disable-sdl \
	    --disable-virtfs \
	    --enable-vnc \
	    --audio-drv-list="" \
	    --audio-card-list="" \
	    --disable-xen \
	    --disable-brlapi \
	    --disable-vnc-tls \
	    --disable-vnc-sasl \
	    --disable-vnc-jpeg \
	    --disable-vnc-png \
	    --enable-curl \
	    --disable-fdt \
	    --disable-bluez \
	    --disable-slirp \
	    --disable-kvm \
	    --disable-nptl \
	    --enable-pie \
	    --cpu="mipsel" \
	    --disable-uuid \
	    --disable-vde \
	    --disable-linux-aio \
	    --disable-cap-ng \
	    --disable-attr \
	    --disable-docs \
	    --enable-vhost-net \
	    --enable-trace-backend="nop" \
	    --disable-spice \
	    --enable-guest-agent \
	    --disable-libiscsi \
	    --disable-smartcard \
	    --disable-seccomp \
	    --disable-glusterfs \
	    --extra-cflags="$(TARGET_CFLAGS)" \
	    --extra-ldflags="$(TARGET_LDFLAGS)" \
	    --disable-zlib-test \
    );
endef
#	    --enable-curses \
#	    --enable-usb-redir \

define Build/Compile
    $(MAKE) -C $(PKG_BUILD_DIR) \
	CC="$(TARGET_CC)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	KBUILD_HAVE_NLS=no \
	EXTRA_CFLAGS="$(TARGET_CFLAGS)" \
	ARCH="$(ARCH)" \
	SKIP_STRIP=y  -lpthread -lzlib \
	CONFIG_PREFIX="$(PKG_INSTALL_DIR)" -lpthread -lzlib \
	install
#	all
#    rm -rf $(PKG_INSTALL_DIR)
#    $(MAKE) -C $(PKG_BUILD_DIR) \
#	CC="$(TARGET_CC)" \
#	CROSS_COMPILE="$(TARGET_CROSS)" \
#	EXTRA_CFLAGS="$(TARGET_CFLAGS)" \
#	ARCH="$(ARCH)" \
#	CONFIG_PREFIX="$(PKG_INSTALL_DIR)" -lpthread -lzlib \
#	install
endef

define Package/qemu/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/qemu $(1)/opt/bin
endef

$(eval $(call BuildPackage,qemu))
