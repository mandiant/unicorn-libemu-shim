#ifndef emu_cpu_H
#define emu_cpu_H

/*
   libemu / Unicorn compatibility shim layer 
   Contributed by FireEye FLARE team
   Author: David Zimmer <david.zimmer@fireeye.com> <dzzie@yahoo.com>
   License: GPL
*/

//this class traps int value gets/sets so we can do dynamic things as they are accessed...
class CAccessCheck
{ 
    int   index;
    int   role;
    uc_engine* uc;

    public: 
        CAccessCheck(void): index(0), role(0), uc(0){}
        CAccessCheck(int r,uc_engine* engine):index(0), role(r), uc(engine){}
        CAccessCheck(int i, int r,uc_engine* engine): index(i), role(r), uc(engine) {} 
    
    //we are setting the value..
    void operator=(uint32_t v);
    
    //we are accessing the value. note if in a printf you MUST cast to (int)
    operator uint32_t const();

    //support the += and -= operations 
    uint32_t operator +=(uint32_t v){
        uint32_t tmp;        
        tmp = operator uint32_t const();
        tmp += v;
        operator=(tmp);
        return tmp;
    }

    uint32_t operator -=(uint32_t v){
        uint32_t tmp;        
        tmp = operator uint32_t const();
        tmp -= v;
        operator=(tmp);
        return tmp;
    }

};      

//this class activates on use of the [] operators to mimic direct array access
class CRegAccess{ 
  protected:
    int m_mode;
    uc_engine* uc;

  public:
    CRegAccess(void){m_mode=0;uc=0;};
    CRegAccess(int mode,uc_engine* engine){m_mode = mode; uc=engine;}
    CAccessCheck operator[](int index){
         return CAccessCheck(index, this->m_mode, this->uc);
    }

};

class emu_cpu {    
    public:
        uc_engine* uc;
        uc_engine* mem;
        CAccessCheck eip;
        CAccessCheck eflags;
        CRegAccess reg;
        //CRegAccess reg16;
	    //CRegAccess reg8;
        emu_cpu(uc_engine* engine);
};


#endif
