use tokio::time::{sleep, Duration};

pub async fn delay_message_processing(){
    sleep(Duration::from_millis(30)).await;
}