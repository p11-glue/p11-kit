#!/bin/sh

source="$1"
target="$2"

rm -f $target-t $target && \
    { echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
      echo; \
      echo '#include <stdlib.h>'; \
      echo '#include "p11-kit/p11-kit.h"'; \
      cat $source; \
      echo "void *${target}_funcs[] = {" | sed 's/[^][ *a-z0-9_={]/_/g'; \
      sed -n -e '/^typedef/d' -e 's/.* \(p11_kit_[^ ]*\) *(.*/	\1,/p' $source; \
      echo '};'; \
    } > $target-t && \
    mv -f $target-t $target
