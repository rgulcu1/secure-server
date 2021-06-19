package response;

import model.NotificateImage;
import org.json.JSONArray;

import java.util.List;


public class NotificationResponse extends Response{

    private List<NotificateImage> imageInfos;

    public NotificationResponse(Integer statusCode, String message, List<NotificateImage> imageInfos) {
        super(statusCode, message);
        this.imageInfos = imageInfos;
    }
}
