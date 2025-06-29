import { Injectable } from '@nestjs/common';
import { CreateResultDto } from './dto/create-result.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Assignment } from 'src/assignment/entities/assignment.entity';
import { Repository, UpdateResult } from 'typeorm';
import { Result } from './entities/result.entity';
import { User } from 'src/users/entities/user.entity';
import { UpdateResultDto } from './dto/update-result.dto';

@Injectable()
export class ResultsService {
  constructor(
    @InjectRepository(Assignment)
    private readonly assignmentREpo: Repository<Assignment>,

    @InjectRepository(Result)
    private readonly resultRepo: Repository<Result>
  ) { }


  async create(teacher: User, dto: CreateResultDto) {
    const assignment = await this.assignmentREpo.findOne({ where: { id: dto.assignmentId }, relations: ['student', 'model'] });

    if (!assignment) {
      throw new Error('assignment topilmadi')
    }

    const result = this.resultRepo.create({
      assignment,
      teacher,
      score: dto.score,
      feedback: dto.feedback
    });
    return this.resultRepo.save(result)
  }

  async findAllByStudent(studentId: number) {
    return this.resultRepo.find({ where: { assignment: { student: { id: studentId } } }, relations: ['assignment', 'teacher'] });
  }

  async update(id: number, dto: UpdateResultDto) {
    const result = await this.resultRepo.findOne({ where: { id }, relations: ['assignment'] });

    if (!result) {
      throw new Error('result topilmadi')
    }
    Object.assign(result, dto)

    return this.resultRepo.save(result)
  }

  async remove(id: number) {
    const result = await this.resultRepo.findOne({ where: { id } })

    if(!result){
      throw new Error
    }
    return this.resultRepo.remove(result)
  }

}
