use types::Msg;

use super::Context;

impl Context {
    // A function's input parameter needs to be borrowed as mutable only when
    // we intend to modify the variable in the function. Otherwise, it need not be borrowed as mutable.
    // In this example, the mut can (and must) be removed because we are not modifying the Context inside
    // the function.

    pub async fn handle_ping(self: &mut Context, msg: Msg) {
        log::info!(
            "Received ping message {:?} from node {}",
            msg.content,
            msg.origin
        );
    }
}
