#ifndef _RAR_ARRAY_
#define _RAR_ARRAY_

#if 0	// COMITTON_MOD
extern ErrorHandler ErrHandler;
#endif

template <class T> class Array
{
  private:
    T *Buffer;
    size_t BufSize;
    size_t AllocSize;
  public:
    Array();
    Array(size_t Size);
    ~Array();
    inline void CleanData();
    inline T& operator [](size_t Item);
    inline size_t Size(); // Returns the size in items, not in bytes.
    void Add(size_t Items);
    void Alloc(size_t Items);
    void Reset();
    void operator = (Array<T> &Src);
    void Push(T Item);
    T* Addr() {return(Buffer);}
};

template <class T> void Array<T>::CleanData()
{
  Buffer=NULL;
  BufSize=0;
  AllocSize=0;
}


template <class T> Array<T>::Array()
{
  CleanData();
}


template <class T> Array<T>::Array(size_t Size)
{
  Buffer=(T *)malloc(sizeof(T)*Size);
  if (Buffer==NULL && Size!=0)
#if 0	// COMITTON_MOD
    ErrHandler.MemoryError();
#else
    LOGE("Array::Array - malloc error.(%d)", (int)(sizeof(T)*Size));
#endif

  AllocSize=BufSize=Size;
}


template <class T> Array<T>::~Array()
{
  if (Buffer!=NULL)
    free(Buffer);
}


template <class T> inline T& Array<T>::operator [](size_t Item)
{
  return(Buffer[Item]);
}


template <class T> inline size_t Array<T>::Size()
{
  return(BufSize);
}


template <class T> void Array<T>::Add(size_t Items)
{
  BufSize+=Items;
  if (BufSize>AllocSize)
  {
    size_t Suggested=AllocSize+AllocSize/4+32;
    size_t NewSize=Max(BufSize,Suggested);

    Buffer=(T *)realloc(Buffer,NewSize*sizeof(T));
    if (Buffer==NULL)
#if 0	// COMITTON_MOD
      ErrHandler.MemoryError();
#else
      LOGE("Array.Add - malloc error.(%d)", /*Buffer,*/(int)(NewSize*sizeof(T)));
#endif
    AllocSize=NewSize;
  }
}


template <class T> void Array<T>::Alloc(size_t Items)
{
  if (Items>AllocSize)
    Add(Items-BufSize);
  else
    BufSize=Items;
}


template <class T> void Array<T>::Reset()
{
  if (Buffer!=NULL)
  {
    free(Buffer);
    Buffer=NULL;
  }
  BufSize=0;
  AllocSize=0;
}


template <class T> void Array<T>::operator =(Array<T> &Src)
{
  Reset();
  Alloc(Src.BufSize);
  if (Src.BufSize!=0)
    memcpy((void *)Buffer,(void *)Src.Buffer,Src.BufSize*sizeof(T));
}


template <class T> void Array<T>::Push(T Item)
{
  Add(1);
  (*this)[Size()-1]=Item;
}

#endif
