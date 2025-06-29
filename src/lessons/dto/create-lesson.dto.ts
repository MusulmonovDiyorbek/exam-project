import { IsNotEmpty, IsNumber, IsString } from "class-validator";

export class CreateLessonDto {
    @IsString()
    @IsNotEmpty()
    title: string;

    @IsString()
    @IsNotEmpty()
    content: string;

    @IsNumber()
    modelId: number;
}
