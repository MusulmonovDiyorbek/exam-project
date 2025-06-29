import { IsNotEmpty, IsNumber, IsOptional, IsString } from "class-validator";

export class CreateResultDto {
    @IsNumber()
    @IsNotEmpty()
    assignmentId:number;

    @IsNumber()
    score:number

    @IsString()
    @IsOptional()
    feedback?:string
}

