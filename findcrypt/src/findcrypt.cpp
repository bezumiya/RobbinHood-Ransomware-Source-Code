// FindCrypt - find constants used in crypto algorithms
// Copyright 2006 Ilfak Guilfanov <ig@hexblog.com>
// This is a freeware program.
// This copytight message must be kept intact.

// This plugin looks for constant arrays used in popular crypto algorithms.
// If a crypto algorithm is found, it will display a message about it on the
// screen and rename the appropriate locations of the program.

// NB: This plugin works only for little endian programs

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <moves.hpp>
#include <set>

#include "findcrypt.hpp"

//--------------------------------------------------------------------------
// check that all constant arrays are distinct (no duplicates)
static void verify_constants(const array_info_t *consts)
{
  typedef std::set<string> strset_t;
  strset_t myset;
  for ( const array_info_t *ptr=consts; ptr->size != 0; ptr++ )
  {
    string s((char*)ptr->array, ptr->size);
    if ( !myset.insert(s).second )
      error("duplicate array %s!", ptr->name);
  }
}

//--------------------------------------------------------------------------
// match a constant array against the database at the specified address
static bool match_array_pattern(ea_t ea, const array_info_t *ai)
{
  const uchar *ptr = (const uchar*)ai->array;
  for ( size_t i=0; i < ai->size; i++ )
    if ( get_byte(ea+i) != ptr[i] )
      return false;
  return true;
}

//--------------------------------------------------------------------------
// match a sparse array against the database at the specified address
static bool match_sparse_pattern(ea_t ea, const array_info_t *ai)
{
  const word32 *ptr = (const word32*)ai->array;
  if ( get_long(ea) != *ptr++ )
    return false;
  ea += 4;
  int n = ai->size / 4;
  for ( size_t i=1; i < n; i++ )
  {
    word32 c = *ptr++;
    // look for the constant in the next N bytes
    const size_t N = 64;
    uchar mem[N+4];
    get_many_bytes(ea, mem, sizeof(mem));
    int j;
    for ( j=0; j < N; j++ )
      if ( *(uint32*)(mem+j) == c )
        break;
    if ( j == N )
      return false;
    ea += j + 4;
  }
  return true;
}

//--------------------------------------------------------------------------
// mark a location with the name of the algorithm
// use the first free slot for the marker
static void mark_location(ea_t ea, const char *name)
{
  char buf[MAXSTR];
  curloc cl;
  cl.ea = ea;
  cl.target = ea;
  cl.x = 0;
  cl.y = 5;
  cl.lnnum = 0;
  cl.flags = 0;
  // find free marked location slot
  int i;
  for ( i=1; i <= MAX_MARK_SLOT; i++ )
    if ( cl.markdesc(i, buf, sizeof(buf)) <= 0 )
      break;
  if ( i <= MAX_MARK_SLOT )
  {
    qsnprintf(buf, sizeof(buf), "Crypto: %s", name);
    cl.mark(i, NULL, buf);
  }
}

//--------------------------------------------------------------------------
// try to find constants at the given address range
static void recognize_constants(ea_t ea1, ea_t ea2)
{
  int count = 0;
  show_wait_box("Searching for crypto constants...");
  for ( ea_t ea=ea1; ea < ea2; ea=nextaddr(ea) )
  {
    if ( (ea % 0x1000) == 0 )
    {
      showAddr(ea);
      if ( wasBreak() )
        break;
    }
    uchar b = get_byte(ea);
    // check against normal constants
    for ( const array_info_t *ptr=non_sparse_consts; ptr->size != 0; ptr++ )
    {
      if ( b != *(uchar*)ptr->array )
        continue;
      if ( match_array_pattern(ea, ptr) )
      {
        msg("%a: found const array %s (used in %s)\n", ea, ptr->name, ptr->algorithm);
        mark_location(ea, ptr->algorithm);
        do_name_anyway(ea, ptr->name);
        count++;
        break;
      }
    }
    // check against sparse constants
    for ( const array_info_t *ptr=sparse_consts; ptr->size != 0; ptr++ )
    {
      if ( b != *(uchar*)ptr->array )
        continue;
      if ( match_sparse_pattern(ea, ptr) )
      {
        msg("%a: found sparse constants for %s\n", ea, ptr->algorithm);
        mark_location(ea, ptr->algorithm);
        count++;
        break;
      }
    }
  }
  hide_wait_box();
  if ( count != 0 )
    warning("Found %d known constant arrays.\n"
            "See the message window for details.",
            count);
}

//--------------------------------------------------------------------------
void run(int)
{
  ea_t ea1, ea2;
  read_selection(&ea1, &ea2); // if fails, inf.minEA and inf.maxEA will be used
  recognize_constants(ea1, ea2);
}

//--------------------------------------------------------------------------
int init(void)
{
//  verify_constants(non_sparse_consts);
//  verify_constants(sparse_consts);
  // agree to work with any database
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void term(void)
{
}

//--------------------------------------------------------------------------
char help[] = "Find crypt";
char comment[] = "Find crypt";
char wanted_name[] = "Find crypt";
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

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
