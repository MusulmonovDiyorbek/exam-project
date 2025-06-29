import { IsNotEmpty, IsNumber, IsString } from "class-validator";

export class CreateModelDto {
    @IsString()
    @IsNotEmpty()
    title:string;

    @IsNumber()
    courseId:number;
}

