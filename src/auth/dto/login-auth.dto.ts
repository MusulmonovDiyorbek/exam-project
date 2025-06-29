import { IsEmail, IsString, IsStrongPassword } from "class-validator";

export class loginAuthDto {
    @IsEmail()
    email: string;
    @IsString()
    password: string;

}
