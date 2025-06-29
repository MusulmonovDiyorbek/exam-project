import { ConflictException, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import { Repository, ReturningStatementNotSupportedError } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository:Repository<User>){}
  async create(dto:CreateUserDto):Promise<User>{
    const uniqueEmail = await this.userRepository.findOneBy({email:dto.email});
    if(uniqueEmail){
      throw new ConflictException('Bu email allaqachon mavjud');
    }
    const user = this.userRepository.create(dto);
    return this.userRepository.save(user);
  } 
  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }
  async findOne(id:number):Promise<User>{
    const user = await this.userRepository.findOneBy({id})
    if(!user){
      throw new ConflictException('Bunday foydalanuvchi mavjud emas');
    }
    return user;
  }
  async findByEmail(email:string):Promise<User>{
    const user = await this.userRepository.findOneBy({email});
    if(!user){
      throw new ConflictException('Bunday email mavjud emas');
    }
    return user;
  }
  async update(id:number,dto:UpdateUserDto):Promise<User>{
    const user =await this.findOne(id);
    const updatedUser = Object.assign(user,dto);
    return this.userRepository.save(updatedUser);
  }
  async remove(id: number): Promise<void> {
    const user = await this.findOne(id);
    await this.userRepository.remove(user);
  }
}
