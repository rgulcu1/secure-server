package response;

import org.json.JSONArray;


public class NotificationResponse extends Response{

    private String imageInfos;

    public NotificationResponse(Integer statusCode, String message, String  imageInfos) {
        super(statusCode, message);
        this.imageInfos = imageInfos;
    }
}
