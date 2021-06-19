package response;




public class RegisterResponse extends Response {

    private String certificate;

    public RegisterResponse(Integer statusCode, String message, String certificate) {
        super(statusCode, message);
        this.certificate = certificate;
    }
}
