package model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ImageInfo {

    private String image;

    private String imageName;

    private String owner;

    private String key;

    private String signature;

    private String IV;

}
