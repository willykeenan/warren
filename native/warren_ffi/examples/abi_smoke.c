#include "warren_native_v1.h"
#include <assert.h>
#include <stddef.h>
_Static_assert(sizeof(wr_result_v1)==24,"result layout");
_Static_assert(offsetof(wr_public_identity_v1,noise_static_public_key)==40,"identity layout");
int main(void) {
  assert(wr_v1_abi_version()==WR_ABI_V1);
  wr_result_v1 out={.struct_size=sizeof(out),.flags=99,.count=99,.value=99};
  assert(wr_v1_start(0,0,1,&out)==WR_INVALID_HANDLE);
  assert(out.flags==0 && out.count==0 && out.value==0);
  assert(wr_v1_operation_cancel(0)==WR_INVALID_HANDLE);
  assert(wr_v1_stream_close(0,1)==WR_INVALID_HANDLE);
  return 0;
}
