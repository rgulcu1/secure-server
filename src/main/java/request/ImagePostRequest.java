package request;

import lombok.Data;

@Data
public class ImagePostRequest{

    private String image;

    private String imageName;

    private String digitalSignature;

    private String owner;

    private String IV;

    private String key;
}
