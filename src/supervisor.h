#ifndef HSP_SUPERVISOR_H
#define HSP_SUPERVISOR_H
#include "config.h"
/* Local IPC only; not part of the network protocol. */
enum ui_state { UI_WAIT_CARD, UI_PIN_REQUIRED, UI_AUTHENTICATING, UI_WAIT_PEER,
                UI_CONNECTING, UI_ESTABLISHED, UI_ERROR, UI_STOPPED };
enum ui_reason { UI_OK, UI_NO_CARD, UI_CARD_SERVICE, UI_PIN_BLOCKED,
                 UI_BAD_PIN, UI_LOGIN_FAILED, UI_BAD_IDENTITY, UI_CARD_LOST,
                 UI_CONFIG_ERROR, UI_STARTUP_ERROR, UI_BUSY, UI_PIN_LOW, UI_PIN_FINAL };
struct supervisor { int fd, locks[3]; uint64_t seen, sent; bool stop, rekey; };
bool supervisor_init(struct supervisor *,int,uint64_t);
bool supervisor_claim(struct supervisor *,const struct config *);
bool supervisor_poll(struct supervisor *,uint64_t);
bool supervisor_healthy(const struct supervisor *,uint64_t);
void supervisor_status(struct supervisor *,const struct config *,const struct peer *,
                       enum ui_state,enum ui_reason,uint64_t,bool,uint64_t);
#endif
