import { IsNotEmpty, IsNumber, IsString } from "class-validator";

export class CreateAssignmentDto {
    @IsString()
    @IsNotEmpty()
    content:string

    @IsNumber()
    modelId:number
}
