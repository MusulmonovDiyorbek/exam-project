import { IsEmail, IsIn, IsNotEmpty, IsOptional, IsString, IsStrongPassword, Min, MIN } from "class-validator";

export class RegisterAuthDto {
    @IsString()
    @IsOptional()
    name: string;

    @IsString()
    @IsNotEmpty()
    username: string;

    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsNotEmpty()
    @IsString()
    password: string;

    @IsIn(['student', 'teacher', 'admin'])
    role: 'student' | 'teacher' | 'admin';

}
