
/* WARNING: Control flow encountered bad instruction data */

void __fastcall entry(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  char cVar1;
  undefined uVar2;
  char cVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  HMODULE hModule;
  FARPROC pFVar7;
  DWORD extraout_EAX;
  DWORD flNewProtect;
  DWORD *pDVar8;
  undefined4 *puVar9;
  uint uVar10;
  uint uVar11;
  FARPROC *ppFVar12;
  uint unaff_EBP;
  uint *puVar13;
  UINT unaff_EDI;
  undefined4 *puVar14;
  DWORD *lpProcName;
  DWORD *pDVar15;
  DWORD *pDVar16;
  bool bVar17;
  bool bVar18;
  undefined4 uStack12;
  undefined4 uStack8;
  
  puVar13 = &DAT_00569015;
  puVar14 = (undefined4 *)&DAT_00401000;
LAB_0062eeda:
  uVar10 = *puVar13;
  bVar17 = puVar13 < (uint *)0xfffffffc;
  puVar13 = puVar13 + 1;
  bVar18 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar17);
  uVar10 = uVar10 * 2 + (uint)bVar17;
LAB_0062eee1:
  if (!bVar18) {
    iVar5 = 1;
    do {
      bVar17 = CARRY4(uVar10,uVar10);
      uVar11 = uVar10 * 2;
      if (uVar11 == 0) {
        uVar10 = *puVar13;
        bVar18 = puVar13 < (uint *)0xfffffffc;
        puVar13 = puVar13 + 1;
        bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
        uVar11 = uVar10 * 2 + (uint)bVar18;
      }
      uVar6 = iVar5 * 2 + (uint)bVar17;
      uVar10 = uVar11 * 2;
      if (CARRY4(uVar11,uVar11)) {
        if (uVar10 != 0) goto LAB_0062ef23;
        uVar11 = *puVar13;
        bVar17 = puVar13 < (uint *)0xfffffffc;
        puVar13 = puVar13 + 1;
        uVar10 = uVar11 * 2 + (uint)bVar17;
        if (CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar17)) goto LAB_0062ef23;
      }
      bVar17 = CARRY4(uVar10,uVar10);
      uVar10 = uVar10 * 2;
      if (uVar10 == 0) {
        uVar10 = *puVar13;
        bVar18 = puVar13 < (uint *)0xfffffffc;
        puVar13 = puVar13 + 1;
        bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
        uVar10 = uVar10 * 2 + (uint)bVar18;
      }
      iVar5 = (uVar6 - 1) * 2 + (uint)bVar17;
    } while( true );
  }
  uVar2 = *(undefined *)puVar13;
  puVar13 = (uint *)((int)puVar13 + 1);
  *(undefined *)puVar14 = uVar2;
  puVar14 = (undefined4 *)((int)puVar14 + 1);
  goto LAB_0062eed6;
LAB_0062ef23:
  iVar5 = 0;
  if (uVar6 < 3) {
    bVar17 = CARRY4(uVar10,uVar10);
    uVar10 = uVar10 * 2;
    if (uVar10 == 0) {
      uVar10 = *puVar13;
      bVar18 = puVar13 < (uint *)0xfffffffc;
      puVar13 = puVar13 + 1;
      bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
      uVar10 = uVar10 * 2 + (uint)bVar18;
    }
  }
  else {
    uVar2 = *(undefined *)puVar13;
    puVar13 = (uint *)((int)puVar13 + 1);
    uVar11 = CONCAT31((int3)uVar6 + -3,uVar2) ^ 0xffffffff;
    if (uVar11 == 0) {
      puVar13 = (uint *)&DAT_00401000;
      iVar5 = 0x6571;
      goto LAB_0062efb2;
    }
    bVar17 = (uVar11 & 1) != 0;
    unaff_EBP = (int)uVar11 >> 1;
  }
  if (!bVar17) {
    iVar5 = 1;
    bVar17 = CARRY4(uVar10,uVar10);
    uVar10 = uVar10 * 2;
    if (uVar10 == 0) {
      uVar10 = *puVar13;
      bVar18 = puVar13 < (uint *)0xfffffffc;
      puVar13 = puVar13 + 1;
      bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
      uVar10 = uVar10 * 2 + (uint)bVar18;
    }
    if (!bVar17) {
      do {
        do {
          bVar17 = CARRY4(uVar10,uVar10);
          uVar11 = uVar10 * 2;
          if (uVar11 == 0) {
            uVar10 = *puVar13;
            bVar18 = puVar13 < (uint *)0xfffffffc;
            puVar13 = puVar13 + 1;
            bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
            uVar11 = uVar10 * 2 + (uint)bVar18;
          }
          iVar5 = iVar5 * 2 + (uint)bVar17;
          uVar10 = uVar11 * 2;
        } while (!CARRY4(uVar11,uVar11));
        if (uVar10 != 0) break;
        uVar11 = *puVar13;
        bVar17 = puVar13 < (uint *)0xfffffffc;
        puVar13 = puVar13 + 1;
        uVar10 = uVar11 * 2 + (uint)bVar17;
      } while (!CARRY4(uVar11,uVar11) && !CARRY4(uVar11 * 2,(uint)bVar17));
      iVar5 = iVar5 + 2;
      goto LAB_0062ef75;
    }
  }
  bVar17 = CARRY4(uVar10,uVar10);
  uVar10 = uVar10 * 2;
  if (uVar10 == 0) {
    uVar10 = *puVar13;
    bVar18 = puVar13 < (uint *)0xfffffffc;
    puVar13 = puVar13 + 1;
    bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
    uVar10 = uVar10 * 2 + (uint)bVar18;
  }
  iVar5 = iVar5 * 2 + (uint)bVar17;
LAB_0062ef75:
  uVar11 = iVar5 + 2 + (uint)(unaff_EBP < 0xfffffb00);
  puVar9 = (undefined4 *)((int)puVar14 + unaff_EBP);
  if (unaff_EBP < 0xfffffffd) {
    do {
      uVar4 = *puVar9;
      puVar9 = puVar9 + 1;
      *puVar14 = uVar4;
      puVar14 = puVar14 + 1;
      bVar17 = 3 < uVar11;
      uVar11 = uVar11 - 4;
    } while (bVar17 && uVar11 != 0);
    puVar14 = (undefined4 *)((int)puVar14 + uVar11);
  }
  else {
    do {
      uVar2 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      *(undefined *)puVar14 = uVar2;
      puVar14 = (undefined4 *)((int)puVar14 + 1);
      uVar11 = uVar11 - 1;
    } while (uVar11 != 0);
  }
LAB_0062eed6:
  bVar18 = CARRY4(uVar10,uVar10);
  uVar10 = uVar10 * 2;
  if (uVar10 == 0) goto LAB_0062eeda;
  goto LAB_0062eee1;
  do {
    while ((1 < (byte)(cVar3 + 0x18U) || (*(char *)puVar13 != '\x15'))) {
LAB_0062efb2:
      cVar3 = *(char *)puVar13;
      puVar13 = (uint *)((int)puVar13 + 1);
    }
    uVar10 = *puVar13;
    cVar3 = *(char *)(puVar13 + 1);
    *(undefined1 **)puVar13 =
         &DAT_00401000 +
         (((uint)(CONCAT21((short)(uVar10 >> 8),(char)(uVar10 >> 0x10)) & 0xffff) << 8 |
          uVar10 >> 0x18) - (int)puVar13);
    puVar13 = (uint *)((int)puVar13 + 5);
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  lpProcName = &DAT_0062d000;
  uStack12 = param_2;
  uStack8 = param_1;
  do {
    flNewProtect = *lpProcName;
    if (flNewProtect == 0) {
LAB_0062f026:
      VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,4,(PDWORD)&stack0xffffffe0);
                    /* WARNING: Read-only address (ram,0x0040019f) is written */
      IMAGE_SECTION_HEADER_00400178.Characteristics._3_1_ = 0x60;
                    /* WARNING: Read-only address (ram,0x004001c7) is written */
      IMAGE_SECTION_HEADER_004001a0.Characteristics._3_1_ = 0x60;
      VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,flNewProtect,(PDWORD)&stack0xffffffe0);
      do {
      } while (&param_3 != (undefined4 *)&stack0xffffff84);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    ppFVar12 = (FARPROC *)(&DAT_00401000 + lpProcName[1]);
    pDVar16 = lpProcName + 2;
    hModule = LoadLibraryA((LPCSTR)((int)&DWORD_00630000 + flNewProtect));
    while( true ) {
      cVar3 = *(char *)pDVar16;
      lpProcName = (DWORD *)((int)pDVar16 + 1);
      if (cVar3 == '\0') break;
      pDVar8 = lpProcName;
      pDVar15 = lpProcName;
      do {
        pDVar16 = pDVar15;
        if (pDVar8 == (DWORD *)0x0) break;
        pDVar8 = (DWORD *)((int)pDVar8 + -1);
        pDVar16 = (DWORD *)((int)pDVar15 + 1);
        cVar1 = *(char *)pDVar15;
        pDVar15 = pDVar16;
      } while ((char)(cVar3 + -1) != cVar1);
      pFVar7 = GetProcAddress(hModule,(LPCSTR)lpProcName);
      if (pFVar7 == (FARPROC)0x0) {
        ExitProcess(unaff_EDI);
        flNewProtect = extraout_EAX;
        goto LAB_0062f026;
      }
      *ppFVar12 = pFVar7;
      ppFVar12 = ppFVar12 + 1;
    }
  } while( true );
}

