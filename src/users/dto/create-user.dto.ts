import { IsEmail, IsIn, IsString } from "class-validator";

export class CreateUserDto {
    @IsString()
    name:string;
    @IsString()
    username:string;
    @IsEmail()
    email:string;
    @IsString()
    password:string;
    @IsIn(['student', 'teacher', 'admin'])
    role: 'student' | 'teacher' | 'admin';
}
