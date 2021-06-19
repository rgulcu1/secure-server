package request;

import lombok.Data;

@Data
public class PublicKeyRequestModel {

    private String n;

    private String e;
}
