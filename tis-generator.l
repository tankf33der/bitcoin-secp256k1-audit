# PicoLisp tis.config file generator
(de prn (F M)
   (prinl "{")
   (printsp "name" ': (pack F " - " M))
   (prinl ",")
   (printsp "files" ': "all")
   (prinl ",")
   (printsp "cpp-extra-args" ': "-DUSE_FORCE_WIDEMUL_INT64 -I. ")
   (prinl ",")
   (printsp "machdep" ': (text M))
   (prinl ",")
   (printsp "main" ': (text F))
   (prinl)
   (prinl "}") )
(setq
   *M
   (quote
      sparc_64 sparc_32
      # x86_32 x86_64 x86_16
      # armeb_eabi arm_eabi aarch64 aarch64eb
      # rv64ifdq rv32ifdq
      # mips_o32 mips_n32 mips_64 mipsel_64
      # mipsel_n32 apple_ppc_32
   )
   *F
   (quote
      main
   )
   *L
   (make
      (for F *F
         (for M *M
            (link (cons F M)) ) ) ) )
(out "tis.config"
   (prinl "// Auto genetated file")
   (prinl "[")
   (for (L *L L (cdr L))
      (let (F (caar L)  M (cdar L))
         (prn F M)
         (and (cdr L) (prinl ",")) ) )
   (prinl "]") )
(bye)
