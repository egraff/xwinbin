#ifndef X_WIN_BIN_COMPILER_H
#define X_WIN_BIN_COMPILER_H


#define INLINE
#define FORCE_INLINE


#if defined(_MSC_VER)
  #undef INLINE
  #define INLINE __inline

  #undef FORCE_INLINE
  #define FORCE_INLINE __forceinline
#endif /* defined(_MSC_VER) */


#if defined(__GNUC__)
  #undef INLINE
  #define INLINE __inline__

  #undef FORCE_INLINE
  #define FORCE_INLINE __inline__ __attribute__((always_inline))
#endif /* defined(__GNUC__) */


#endif /* X_WIN_BIN_COMPILER_H */
