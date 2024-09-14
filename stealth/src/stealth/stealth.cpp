// Anti-anti-debugger plugin for IDA Pro. (Stealth). Version 1.0.
// Hides IDA Pro from the application and disables some potentially
// dangerous Windows API functions.

// The plugin uses one simple trick: a conditional breakpoint
// at the beginning of an API function so that the breakpoint condition
// changes the execution flow to make the function immediately return
// to the caller without doing anything. Here is a condition example:
//
//  (EIP=retaddr) && (EAX=0)
//
// In other words, we jump to the 'ret' instruction and set EAX to the desired
// value. Zero in the condition can be replaced by any other value we want
// to return from the function.

// Copyright (c) 2005 Ilfak Guilfanov <ig@hexblog.com>
// Freeware.

#include <windows.h>

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>

// Current state of the plugin
static bool enabled = false;

// Name of the netnode in the database
// Use names starting with "$ ". Long names are preferred.
static const char stnode_name[] = "$ ida debugger stealth plugin";

//--------------------------------------------------------------------------
struct bpt_info_t
{
  char *funcname;
  ea_t ea;
  uint32 retvalue;
};

// List of breakpoints to set (address will be determined on the fly)
static bpt_info_t kernel32_bpts[] =
{
  //  Function name             Address Retval Stop
  { "IsDebuggerPresent",        BADADDR,  0 },
  { "SuspendThread",            BADADDR,  1 },
  { "ResumeThread",             BADADDR,  1 },
  { "DebugActiveProcess",       BADADDR,  0 },
  { "DebugActiveProcessStop",   BADADDR,  0 },
  { "TerminateProcess",         BADADDR,  0 },
};

static bpt_info_t user32_bpts[] =
{
  { "BlockInput",               BADADDR,  1 },
};

struct lib_info_t
{
  char *name;
  bpt_info_t *bpts;
  size_t nbpts;
  bool bpts_are_created;
};

static lib_info_t libs[] =
{
  { "kernel32", kernel32_bpts, qnumber(kernel32_bpts) },
  { "user32",   user32_bpts,   qnumber(user32_bpts) },
};

//--------------------------------------------------------------------------
// find a return instruction in the function body
static ea_t find_ret_insn(ea_t ea)
{
  ua_code(ea);
  add_func(ea, BADADDR);
  // functions in the kernel are quite small, 1000 must be enough
  for ( int i=0; i < 1000 && ea != BADADDR; i++ )
  {
    if ( is_ret_insn(ea, true) )
      return ea;
    ea = nextthat(ea, BADADDR, f_isCode, NULL);
  }
  return BADADDR;
}

//--------------------------------------------------------------------------
static void create_bpts_for_lib(lib_info_t &li)
{
  if ( !li.bpts_are_created )
  {
    int success = false;
    bpt_info_t *bpts = li.bpts;
    int nbpts        = li.nbpts;
    for ( size_t j=0; j < nbpts; j++ )
    {
      bpt_info_t &bi = bpts[j];
      char name[MAXNAMELEN];
      qsnprintf(name, sizeof(name), "%s_%s", li.name, bi.funcname);
      ea_t ea = get_name_ea(BADADDR, name);
      if ( ea == BADADDR )
      {
        msg("Could not find API function %s, skipping...\n", name);
        continue;
      }
      ea_t ret = find_ret_insn(ea);
      if ( ret == BADADDR )
      {
        msg("Could not find function return, skipping...\n", name);
        continue;
      }
      add_bpt(ea);
      bpt_t bpt;
      get_bpt(ea, &bpt);
      bpt.flags = 0;//BPT_TRACE;    // don't stop, trace only
      bpt.pass_count = 0;
      qsnprintf(bpt.condition,
                sizeof(bpt.condition),
                "(EIP=0x%a) && (EAX=0x%X)", ret, bi.retvalue);
      if ( !update_bpt(&bpt) )
      {
        msg("Could not set bpt for API function %s, skipping...\n", bi.funcname);
        continue;
      }
      bi.ea = ea;
      success++;
    }
    if ( success > 0 )
    {
      li.bpts_are_created = true;
      msg("Stealth mode breakpoints for %s have been set.\n", li.name);
    }
  }
}

//--------------------------------------------------------------------------
// Create stealth breakpoints for the specified library
// If libname == NULL, then create breakpoints for all libraries
// from_event==true means that this function is called from an event handler
// and the function names are not up to date.
static void create_bpts(const char *libname, bool from_event)
{
  for ( size_t i=0; i < qnumber(libs); i++ )
  {
    if ( !libs[i].bpts_are_created )
    {
      if ( libname == NULL )
      {
        create_bpts_for_lib(libs[i]);
      }
      else if ( stristr(libname, libs[i].name) != NULL )
      {
        // refresh the name list
        if ( from_event )
          dbg->stopped_at_debug_event(true);
        create_bpts_for_lib(libs[i]);
        break;
      }
    }
  }
}

//--------------------------------------------------------------------------
// Delete all breakpoint set by us
static void delete_bpts(void)
{
  for ( size_t i=0; i < qnumber(libs); i++ )
  {
    bpt_info_t *bpts = libs[i].bpts;
    int nbpts        = libs[i].nbpts;
    for ( size_t j=0; j < nbpts; j++ )
    {
      bpt_info_t &bi = bpts[j];
      del_bpt(bi.ea);
      bi.ea = BADADDR;
    }
    libs[i].bpts_are_created = false;
  }
}

//--------------------------------------------------------------------------
// We use this callback function to detect when kernel32.dll is loaded into
// the memory. At this point we set all necessary breapoints.
static int idaapi callback(void * /*user_data*/, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    case dbg_library_load:
      {
        const debug_event_t *pev = va_arg(va, const debug_event_t *);
        create_bpts(pev->modinfo.name, true);
      }
      break;

    case dbg_process_exit:
      delete_bpts();
      break;

  }
  return 0;
}

//--------------------------------------------------------------------------
// arg==0: manual invocation, display a dialog box
// arg <0: no dialogs, disable
// arg >0: no dialogs, enable
// by default the plugin is disabled
void run(int arg)
{
  int code;
  if ( arg == 0 )
  {
    static const char str[] =
    "Stealth mode: hide IDA debugger\n"
    "\n"
    "Currently the stealth mode is %sabled.\n"
    "Do you want to activate the stealth mode?";

    code = askbuttons_c("Enable", "Disable", "Cancel", !enabled, str, enabled ? "en" : "dis");
    if ( code < 0 ) // cancel
      return;
  }
  else
  {
    code = arg > 0;
  }

  // remember the answer in the database
  netnode stnode;
  stnode.create(stnode_name);
  stnode.altset(0, code);

  if ( code )
  {
    if ( !hook_to_notification_point(HT_DBG, callback, NULL) )
    {
      warning("Stealth: could not hook to notification point\n");
      return;
    }
    enabled = true;
    // check if kernel32 is present
    if ( get_name_ea(BADADDR, "kernel32_LoadLibraryA") != BADADDR )
    {
      // yes, hook to bpts immediately
      create_bpts(NULL, false);
    }
  }
  else
  {
    delete_bpts();
    unhook_from_notification_point(HT_DBG, callback, NULL);
    enabled = false;
  }
}

//--------------------------------------------------------------------------
int init(void)
{
  // Our plugin works only for x86 PE executables
  if ( ph.id != PLFM_386 || inf.filetype != f_PE )
    return PLUGIN_SKIP;
  // check if the plugin should immediately be activated
  netnode stnode;
  stnode.create(stnode_name);
  if ( stnode.altval(0) ) // yes
  {
    if ( !hook_to_notification_point(HT_DBG, callback, NULL) )
    {
      warning("Stealth: could not hook to notification point\n");
      return PLUGIN_SKIP;
    }
    enabled = true;
    return PLUGIN_KEEP;
  }
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void term(void)
{
  delete_bpts();
  unhook_from_notification_point(HT_DBG, callback, NULL);
}

//--------------------------------------------------------------------------
char wanted_name[] = "Stealth: hide IDA debugger";
char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  wanted_name,          // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  wanted_name,          // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
