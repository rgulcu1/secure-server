package response;

public class ImageDisplayResponse extends Response{

    private String image;

    private String digitalSignature;

    private String owner;

    private String certificate;

    private String key;

    private String IV;

    public ImageDisplayResponse(Integer statusCode, String message, String image, String digitalSignature, String owner, String certificate, String key, String IV) {
        super(statusCode, message);
        this.image = image;
        this.digitalSignature = digitalSignature;
        this.owner = owner;
        this.certificate = certificate;
        this.key = key;
        this.IV = IV;
    }
}
