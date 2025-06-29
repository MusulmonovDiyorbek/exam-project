import { IsNotEmpty, IsNumber, IsOptional, IsString } from "class-validator";

export class CreateCourseDto {
    @IsString()
    @IsNotEmpty()
    name:string;

    @IsString()
    description:string;

    @IsNumber()
    price:number;
    
    @IsString()
    category:string;

    @IsString()
    level:string;

    @IsNumber()
    teacherId:number;

}

